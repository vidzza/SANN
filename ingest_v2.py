"""
GOD EYE - V2 Comprehensive Ingestion Engine
Full re-process with:
- Participant tracking (user0003/user2003/user4002)
- Attack phase classification (MITRE ATT&CK)
- Clean user extraction
- Command extraction from all sources
- Typed text reconstruction from UAT keystrokes
- Terminal command extraction from .cast files
- bt.jsonl message parsing
- sensor.log packet analysis
- Phase timeline per participant
"""

import json
import re
import sys
import uuid
import sqlite3
import logging
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Iterator, Dict, List, Optional, Tuple

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

# Rutas configurables via variables de entorno o .env
# GODEYE_DATA_ROOT  — carpeta raíz del dataset (contiene user*/...)
# GODEYE_DB_PATH    — ruta al archivo SQLite (se crea si no existe)
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
DATA_ROOT = Path(_os.environ.get('GODEYE_DATA_ROOT', '/tmp/obsidian_full/P003'))
DB_PATH   = Path(_os.environ.get('GODEYE_DB_PATH',
                 str(Path(__file__).parent / 'data' / 'godeye_v2.db')))

# ---------------------------------------------------------------------------
# MITRE ATT&CK Phase classification
# ---------------------------------------------------------------------------
PHASE_RULES = [
    # (regex_on_command_or_action, phase, tactic, technique)
    (r'nmap|masscan|ping|arp-scan|netdiscover|fping|unicornscan', 'recon', 'TA0043', 'T1046'),
    (r'whois|host|dig|nslookup|theHarvester|amass|subfinder|dnsrecon', 'recon', 'TA0043', 'T1018'),
    (r'nikto|dirbuster|gobuster|dirb|ffuf|wfuzz|feroxbuster', 'recon', 'TA0043', 'T1595'),
    (r'sqlmap|sqli|sql.*injection', 'initial_access', 'TA0001', 'T1190'),
    (r'hydra|medusa|john|hashcat|cupp|bruteforce|brute.?force|password.*spray', 'initial_access', 'TA0001', 'T1110'),
    (r'exploit|msf|msfconsole|msfvenom|metasploit|CVE-', 'initial_access', 'TA0001', 'T1203'),
    (r'ssh\s|sshpass|ssh -i|ssh -o', 'lateral_movement', 'TA0008', 'T1021.004'),
    (r'wget|curl.*download|scp |sftp |rsync', 'lateral_movement', 'TA0008', 'T1570'),
    (r'nc |netcat|ncat|socat|reverse.?shell|bind.?shell', 'command_and_control', 'TA0011', 'T1059'),
    (r'whoami|id\b|uname|hostname|ifconfig|ip addr|ip route|cat /etc/passwd', 'discovery', 'TA0007', 'T1033'),
    (r'ps aux|ps -ef|top\b|pstree|lsof|netstat|ss -', 'discovery', 'TA0007', 'T1057'),
    (r'ls -la|find /|locate\b|which\b|cat /etc|cat /proc', 'discovery', 'TA0007', 'T1083'),
    (r'sudo\s|su\s|su -|sudo -i|sudo su|pkexec', 'privilege_escalation', 'TA0004', 'T1548.003'),
    (r'chmod\s|chown\s|setuid|SUID|capabilities', 'privilege_escalation', 'TA0004', 'T1548'),
    (r'crontab|cron\b|/etc/cron|systemctl enable|at\s\d', 'persistence', 'TA0003', 'T1053'),
    (r'rootkit|insmod|modprobe|/proc/modules|lsmod', 'persistence', 'TA0003', 'T1547'),
    (r'useradd|adduser|usermod|passwd\s|/etc/shadow', 'persistence', 'TA0003', 'T1136'),
    (r'tar czf|zip\s|gzip\s|encrypt|openssl.*-e|gpg -c', 'exfiltration', 'TA0010', 'T1560'),
    (r'curl.*PUT|curl.*POST|wget.*post|nc.*\d{1,3}\.\d{1,3}|ftp\s', 'exfiltration', 'TA0010', 'T1048'),
    (r'rm -rf|shred|wipe|dd.*if=/dev/zero|history -c|unset HISTFILE', 'defense_evasion', 'TA0005', 'T1070'),
    (r'iptables|ufw\s|firewall|setenforce\s0|apparmor', 'defense_evasion', 'TA0005', 'T1562'),
    (r'docker\s|kubectl\s|podman\s', 'execution', 'TA0002', 'T1610'),
    (r'python\s|python3\s|perl\s|ruby\s|php\s|bash\s|sh\s', 'execution', 'TA0002', 'T1059'),
]

ROOTKIT_PHASE = 'persistence'
HONEYPOT_PHASE = 'initial_access'
BRUTEFORCE_PHASE = 'initial_access'


def classify_phase(command: str, action_name: str, tool: str, raw_data: str = '') -> Tuple[str, str, str]:
    """Return (phase, mitre_tactic, mitre_technique)"""
    text = f"{command} {action_name} {tool}".lower()
    raw = raw_data.lower()

    # Action-name based rules (fast path — no regex needed)
    _ACTION_PHASE = {
        'sudo_execution':    ('privilege_escalation', 'TA0004', 'T1548'),
        'sudo_session':      ('privilege_escalation', 'TA0004', 'T1548'),
        'user_created':      ('persistence',          'TA0003', 'T1136'),
        'password_changed':  ('credential_access',    'TA0006', 'T1098'),
        'python_execution':  ('execution',            'TA0002', 'T1059'),
        'tool_accessed':     ('execution',            'TA0002', 'T1204'),
        'terminal_command':  ('reconnaissance',       'TA0043', 'T1595'),
        'ui_activity':       ('discovery',            'TA0007', 'T1046'),
        'file_detected':     ('collection',           'TA0009', 'T1005'),
        'ids_notice':        ('discovery',            'TA0007', 'T1046'),
        'capture_loss':      ('defense_evasion',      'TA0005', 'T1562'),
        'video_recording':   ('collection',           'TA0009', 'T1113'),
        'suricata_anomaly':  ('defense_evasion',      'TA0005', 'T1562'),
        'attack_status':     ('command_and_control',  'TA0011', 'T1071'),
        'triggered_query':   ('command_and_control',  'TA0011', 'T1071'),
        'ssh_intercept':     ('command_and_control',  'TA0011', 'T1071'),
        'cron_job':          ('persistence',          'TA0003', 'T1053'),
    }
    if action_name in _ACTION_PHASE:
        return _ACTION_PHASE[action_name]

    # auth/session sub-classification using raw_data
    if action_name == 'session':
        if 'sshd' in raw:
            return 'lateral_movement', 'TA0008', 'T1021'
        if 'cron' in raw:
            return 'persistence', 'TA0003', 'T1053'
        if 'sudo' in raw:
            return 'privilege_escalation', 'TA0004', 'T1548'

    # suricata ids_alert sub-classification
    if action_name == 'ids_alert':
        if 'ssh' in raw:
            return 'lateral_movement', 'TA0008', 'T1021'
        return 'discovery', 'TA0007', 'T1046'

    # suricata/sensor http_traffic sub-classification
    if action_name == 'http_traffic':
        if 'tomcatwar' in raw or 'cmd=' in raw or 'webshell' in raw:
            return 'execution', 'TA0002', 'T1190'
        return 'initial_access', 'TA0001', 'T1190'

    # sensor_packet sub-classification using raw_data content
    if action_name == 'sensor_packet':
        # TODO: attacker_ips is hardcoded for P003 dataset. Make this configurable
        # via .env or a config file so classification works across different datasets.
        attacker_ips = ('122.10.11.101', '122.10.11.102', '114.0.194.2', '114.231.10.3')
        if any(ip in raw_data for ip in attacker_ips):
            return 'command_and_control', 'TA0011', 'T1071'
        if 'sec-workstation' in raw:
            return 'discovery', 'TA0007', 'T1046'
        if ('payload' in raw and 'username' in raw) or ('payload' in raw and 'password' in raw):
            return 'credential_access', 'TA0006', 'T1110'
        if 'rtriggerd_query' in raw or 'attack_status' in raw:
            return 'command_and_control', 'TA0011', 'T1071'

    # kernel_event sub-classification
    if action_name == 'kernel_event':
        if 'rootkit' in raw:
            return 'persistence', 'TA0003', 'T1547'
        if 'promiscuous' in raw:
            return 'collection', 'TA0009', 'T1040'

    # syslog runevents C2 beaconing
    if action_name == 'syslog_event' and 'runevents' in raw:
        return 'command_and_control', 'TA0011', 'T1071'

    for pattern, phase, tactic, technique in PHASE_RULES:
        if re.search(pattern, text, re.I):
            return phase, tactic, technique

    # Fallback by action_name keywords
    if 'rootkit' in text:
        return 'persistence', 'TA0003', 'T1547'
    if 'honeypot' in text:
        return 'initial_access', 'TA0001', 'T1190'
    if 'login' in text or 'auth' in text:
        return 'initial_access', 'TA0001', 'T1078'
    if 'network' in text or 'flow' in text:
        return 'recon', 'TA0043', 'T1046'
    if 'docker' in text:
        return 'execution', 'TA0002', 'T1610'
    return 'unknown', '', ''


# ---------------------------------------------------------------------------
# User cleaning
# ---------------------------------------------------------------------------
USER_BLACKLIST = {
    'pam_unix(sudo:session):', 'pam_unix(cron:session):', 'pam_unix(su:session):',
    'message', 'None', '', 'none',
    'pam_unix(sshd:session):', 'pam_unix(login:session):',
}

def clean_user(raw_user: str) -> str:
    if not raw_user:
        return ''
    raw_user = raw_user.strip()
    if raw_user in USER_BLACKLIST:
        return ''
    # Clean pam_unix patterns
    m = re.search(r'for user (\w+)', raw_user)
    if m:
        return m.group(1)
    m = re.search(r'user=(\w+)', raw_user)
    if m:
        return m.group(1)
    # Clean parenthetical
    m = re.match(r'^(\w[\w\-\.]+)', raw_user)
    if m:
        candidate = m.group(1)
        if len(candidate) > 1 and not candidate.startswith('pam_'):
            return candidate
    return ''


# ---------------------------------------------------------------------------
# UAT Keystroke reconstruction
# ---------------------------------------------------------------------------
SPECIAL_KEY_MAP = {
    'Return': '\n', 'space': ' ', 'BackSpace': '\x08',
    'Tab': '\t', 'Escape': '\x1b', 'Delete': '',
    'Left': '', 'Right': '', 'Up': '', 'Down': '',
    'Home': '', 'End': '', 'Page_Up': '', 'Page_Down': '',
    'ctrl': '', 'shift': '', 'alt': '',
}

def reconstruct_typed_text_from_uat(file_path: Path) -> List[Dict]:
    """
    Reconstruct typed commands from UAT keystrokes.
    Returns list of {timestamp, window_title, text} dicts.
    """
    sessions = []
    current_text = []
    current_window = ''
    current_ts = None
    session_ts = None

    try:
        with open(file_path, 'r', errors='ignore') as f:
            for line in f:
                if line.startswith('#'):
                    continue
                parts = line.rstrip('\n').split('\t')
                if len(parts) < 5:
                    continue
                ts_ms = parts[0].strip()
                window_name = parts[3].strip() if len(parts) > 3 else ''
                event_type = parts[4].strip() if len(parts) > 4 else ''
                additional = parts[5].strip() if len(parts) > 5 else ''

                # Only process key-up events
                if 'KU' not in event_type:
                    continue

                try:
                    ts_float = int(ts_ms) / 1000.0
                    current_ts = datetime.utcfromtimestamp(ts_float).isoformat()
                except:
                    current_ts = ts_ms

                # Window changed: save current session
                if window_name != current_window and current_window:
                    text = _build_text_from_chars(current_text)
                    if text.strip():
                        for cmd in text.split('\n'):
                            cmd = cmd.strip()
                            if cmd:
                                sessions.append({
                                    'timestamp': session_ts,
                                    'window': current_window,
                                    'typed_text': cmd,
                                })
                    current_text = []
                    session_ts = current_ts

                if not session_ts:
                    session_ts = current_ts
                current_window = window_name

                # Parse key
                kparts = additional.split(',')
                if len(kparts) < 2:
                    continue
                char = kparts[1]
                ktype = kparts[2].strip() if len(kparts) > 2 else ''

                if ktype in ('Letter', 'Number', 'Symbol'):
                    current_text.append(char)
                elif char in SPECIAL_KEY_MAP:
                    mapped = SPECIAL_KEY_MAP[char]
                    if mapped == '\n':
                        # Command submitted
                        text = _build_text_from_chars(current_text)
                        if text.strip():
                            sessions.append({
                                'timestamp': session_ts,
                                'window': current_window,
                                'typed_text': text.strip(),
                            })
                        current_text = []
                        session_ts = current_ts
                    elif mapped == '\x08':
                        if current_text:
                            current_text.pop()
                    else:
                        current_text.append(mapped)

        # Flush
        if current_text:
            text = _build_text_from_chars(current_text)
            if text.strip():
                sessions.append({
                    'timestamp': session_ts,
                    'window': current_window,
                    'typed_text': text.strip(),
                })
    except Exception as e:
        logger.debug(f"UAT parse error {file_path}: {e}")

    return sessions


def _build_text_from_chars(chars: List[str]) -> str:
    result = []
    for c in chars:
        if c == '\x08':
            if result:
                result.pop()
        else:
            result.append(c)
    return ''.join(result)


# ---------------------------------------------------------------------------
# Cast file command extraction
# ---------------------------------------------------------------------------
def extract_commands_from_cast(file_path: Path) -> List[Dict]:
    """Extract commands typed in cast terminal recording with accurate per-command timestamps.

    Each asciinema v2 event has [relative_seconds, type, data].  We accumulate
    output segments with their wall-clock abs_ts (= header.timestamp + rel_ts)
    and, after stripping ANSI codes, detect prompt lines.  The timestamp
    assigned to each command is the abs_ts of the output segment that contained
    the prompt — giving accurate wall-clock times instead of the cast start.
    """
    commands = []
    try:
        with open(file_path, 'r', errors='ignore') as f:
            lines = f.readlines()

        if not lines:
            return commands

        # Parse header
        try:
            header = json.loads(lines[0])
            base_ts = header.get('timestamp', 0)
        except:
            base_ts = 0

        # Collect output segments with per-segment abs_ts
        output_segments = []  # list of (abs_ts: float, data: str)
        for line in lines[1:]:
            try:
                entry = json.loads(line)
                if isinstance(entry, list) and len(entry) >= 3:
                    rel_ts, etype, data = entry[0], entry[1], entry[2]
                    if etype == 'o':
                        abs_ts = base_ts + rel_ts
                        output_segments.append((abs_ts, data))
            except:
                continue

        # Strip ANSI escape codes per segment, preserving (abs_ts, clean_text) pairs
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        clean_segments = [(ts, ansi_escape.sub('', d)) for ts, d in output_segments]

        # Reconstruct a character stream annotated with timestamps.
        # Build list of (abs_ts, char) then split on newlines to get
        # (abs_ts_of_line, line_text) where abs_ts is the timestamp of the
        # FIRST character in that line (i.e. when the prompt appeared).
        char_stream = []  # (abs_ts, char)
        for ts, text in clean_segments:
            for ch in text:
                char_stream.append((ts, ch))

        # Split into lines, keeping timestamp of first char in each line
        line_ts   = base_ts  # fallback
        line_buf  = []
        lines_with_ts = []  # list of (abs_ts, line_str)
        for ts, ch in char_stream:
            if ch in ('\n', '\r'):
                if line_buf:
                    lines_with_ts.append((line_ts, ''.join(line_buf)))
                    line_buf = []
                    line_ts = ts  # next line starts at this timestamp
            else:
                if not line_buf:
                    line_ts = ts  # record timestamp of first char in new line
                line_buf.append(ch)
        if line_buf:
            lines_with_ts.append((line_ts, ''.join(line_buf)))

        # Detect prompt lines and extract command + accurate timestamp
        prompt_re = re.compile(r'(?:[\$#]\s+|>>>\s+)(.+)')
        for abs_ts, line_text in lines_with_ts:
            m = prompt_re.search(line_text)
            if m:
                cmd = m.group(1).strip()
                if cmd and len(cmd) > 1 and not cmd.startswith('\\'):
                    ts_str = datetime.utcfromtimestamp(abs_ts).isoformat() if abs_ts else None
                    commands.append({
                        'timestamp': ts_str,
                        'command': cmd,
                        'file': str(file_path),
                    })
    except Exception as e:
        logger.debug(f"Cast parse error {file_path}: {e}")

    return commands


# ---------------------------------------------------------------------------
# Command extraction from raw_data
# ---------------------------------------------------------------------------
COMMAND_PATTERNS = [
    re.compile(r'COMMAND=(.+?)(?:\s*$|\s+PWD=|\s+USER=)', re.M),
    re.compile(r'CMD\s*[=:]\s*(.+?)(?:\r?\n|$)', re.M),
    re.compile(r'command["\s:=]+([^\s"][^"]+?)["$\n]', re.I),
    re.compile(r'ExecRewriteGetRules["\']?\s*[:\-]\s*(.+?)(?:\r?\n|$)', re.M),
    re.compile(r'"cmd"\s*:\s*"([^"]+)"'),
    re.compile(r'Executing:\s*(.+?)(?:\r?\n|$)', re.M),
    re.compile(r'exec[uted]*[:\s]+(.+?)(?:\r?\n|$)', re.I | re.M),
]

def extract_command(raw_data: str, message: str = '') -> str:
    """Extract command from raw_data string."""
    for pattern in COMMAND_PATTERNS:
        m = pattern.search(raw_data)
        if m:
            cmd = m.group(1).strip().strip('"\'')
            if cmd and len(cmd) > 1:
                return cmd

    # Try from message field
    if message:
        # Docker container commands
        m = re.search(r'docker exec.+?(["\']?)(.+?)\1(?:\r?\n|$)', message)
        if m:
            return m.group(2).strip()
        # Generic exec
        m = re.search(r'(?:run|exec|execute)[s\s:]+(.+?)(?:\r?\n|$)', message, re.I)
        if m:
            cmd = m.group(1).strip()
            if len(cmd) > 1:
                return cmd

    return ''


def extract_user_from_raw(raw_data: str) -> str:
    """Extract clean user from raw log line."""
    patterns = [
        r'sudo:\s+(\w+)\s*:', 
        r'for user (\w+)\b',
        r'user=(\w+)',
        r'USER=(\w+)',
        r'Accepted.*for (\w+) from',
        r'Failed.*for (\w+) from',
        r'session opened for user (\w+)',
        r'session closed for user (\w+)',
        r'Invalid user (\w+)',
        r'su.*for (\w+)\b',
    ]
    for p in patterns:
        m = re.search(p, raw_data)
        if m:
            u = m.group(1).strip()
            if u and u not in USER_BLACKLIST and len(u) > 1:
                return u
    return ''


# ---------------------------------------------------------------------------
# DB Schema v2
# ---------------------------------------------------------------------------
SCHEMA_V2 = '''
CREATE TABLE IF NOT EXISTS events (
    event_id         TEXT PRIMARY KEY,
    participant_id   TEXT,
    scenario_name    TEXT,
    timestamp_utc    TEXT,
    source_type      TEXT,
    source_file      TEXT,
    source_host      TEXT,
    src_ip           TEXT,
    src_port         INTEGER DEFAULT 0,
    dest_ip          TEXT,
    dest_port        INTEGER DEFAULT 0,
    protocol         TEXT,
    user             TEXT,
    action_category  TEXT,
    action_name      TEXT,
    tool             TEXT,
    result           TEXT,
    command          TEXT,
    typed_text       TEXT,
    arguments        TEXT,
    working_dir      TEXT,
    process_id       INTEGER DEFAULT 0,
    attack_phase     TEXT,
    mitre_tactic     TEXT,
    mitre_technique  TEXT,
    alert_type       TEXT,
    alert_severity   INTEGER DEFAULT 0,
    detection_source TEXT,
    http_method      TEXT,
    url              TEXT,
    user_agent       TEXT,
    http_status      INTEGER DEFAULT 0,
    raw_data         TEXT,
    extra_data       TEXT
);
CREATE INDEX IF NOT EXISTS idx_ts      ON events(timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_part    ON events(participant_id);
CREATE INDEX IF NOT EXISTS idx_scen    ON events(scenario_name);
CREATE INDEX IF NOT EXISTS idx_phase   ON events(attack_phase);
CREATE INDEX IF NOT EXISTS idx_host    ON events(source_host);
CREATE INDEX IF NOT EXISTS idx_user    ON events(user);
CREATE INDEX IF NOT EXISTS idx_tool    ON events(tool);
CREATE INDEX IF NOT EXISTS idx_action  ON events(action_name);
CREATE INDEX IF NOT EXISTS idx_srctype ON events(source_type);
'''

INSERT_SQL = '''
INSERT OR REPLACE INTO events VALUES (
    ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?
)
'''


class DBv2:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path))
        self.conn.execute('PRAGMA journal_mode=WAL')
        self.conn.execute('PRAGMA synchronous=NORMAL')
        for stmt in SCHEMA_V2.strip().split(';'):
            s = stmt.strip()
            if s:
                self.conn.execute(s)
        self.conn.commit()
        self._buf = []

    def insert(self, e: dict):
        self._buf.append((
            e.get('event_id', str(uuid.uuid4())),
            e.get('participant_id', ''),
            e.get('scenario_name', ''),
            e.get('timestamp_utc', ''),
            e.get('source_type', ''),
            e.get('source_file', ''),
            e.get('source_host', ''),
            e.get('src_ip', ''),
            int(e.get('src_port', 0) or 0),
            e.get('dest_ip', ''),
            int(e.get('dest_port', 0) or 0),
            e.get('protocol', ''),
            e.get('user', ''),
            e.get('action_category', ''),
            e.get('action_name', ''),
            e.get('tool', ''),
            e.get('result', ''),
            e.get('command', ''),
            e.get('typed_text', ''),
            e.get('arguments', ''),
            e.get('working_dir', ''),
            int(e.get('process_id', 0) or 0),
            e.get('attack_phase', ''),
            e.get('mitre_tactic', ''),
            e.get('mitre_technique', ''),
            e.get('alert_type', ''),
            int(e.get('alert_severity', 0) or 0),
            e.get('detection_source', ''),
            e.get('http_method', ''),
            e.get('url', ''),
            e.get('user_agent', ''),
            int(e.get('http_status', 0) or 0),
            e.get('raw_data', ''),
            e.get('extra_data', ''),
        ))
        if len(self._buf) >= 2000:
            self.flush()

    def flush(self):
        if self._buf:
            self.conn.executemany(INSERT_SQL, self._buf)
            self.conn.commit()
            self._buf = []

    def close(self):
        self.flush()
        self.conn.close()

    def query(self, sql, params=()):
        cur = self.conn.execute(sql, params)
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]


# ---------------------------------------------------------------------------
# Path parsing helpers
# ---------------------------------------------------------------------------
def parse_path_meta(file_path: Path):
    """Extract participant_id, scenario_name, host from file path.

    Rules (structure-agnostic):
      - participant_id : first path component matching user\w+ (any variant)
      - scenario_name  : first non-numeric component immediately after participant_id
                         (whatever it is — no whitelist)
      - host           : immediate parent directory of the file
                         (falls back to scenario_name if file is directly inside it)
    """
    parts = file_path.parts
    participant_id = ''
    scenario_name = ''

    # Find participant dir — any component starting with 'user' followed by alphanumerics
    pid_idx = None
    for i, part in enumerate(parts):
        if re.match(r'user\w+$', part, re.IGNORECASE):
            participant_id = part
            pid_idx = i
            break

    # Scenario = first non-numeric, non-empty component after participant dir
    if pid_idx is not None:
        for part in parts[pid_idx + 1:]:
            if part and not re.match(r'^\d+$', part):
                scenario_name = part
                break

    # Host = immediate parent of the file (most specific context)
    host = file_path.parent.name
    # If host is a pure number or the participant dir itself, use scenario_name
    if re.match(r'^\d+$', host) or host == participant_id:
        host = scenario_name

    return participant_id, scenario_name, host


# ---------------------------------------------------------------------------
# Per-file parsers
# ---------------------------------------------------------------------------

def make_event(participant_id, scenario_name, source_host, source_type, source_file,
               timestamp_utc='', user='', action_category='', action_name='',
               tool='', command='', typed_text='', raw_data='', **kwargs) -> dict:
    user = clean_user(user) or clean_user(extract_user_from_raw(raw_data))
    command = command or extract_command(raw_data)
    phase, tactic, technique = classify_phase(command, action_name, tool, raw_data)
    return {
        'event_id': str(uuid.uuid4()),
        'participant_id': participant_id,
        'scenario_name': scenario_name,
        'timestamp_utc': timestamp_utc,
        'source_type': source_type,
        'source_file': str(source_file),
        'source_host': source_host,
        'user': user,
        'action_category': action_category,
        'action_name': action_name,
        'tool': tool,
        'command': command,
        'typed_text': typed_text,
        'attack_phase': kwargs.get('attack_phase', phase),
        'mitre_tactic': kwargs.get('mitre_tactic', tactic),
        'mitre_technique': kwargs.get('mitre_technique', technique),
        'raw_data': raw_data,
        **{k: v for k, v in kwargs.items() if k not in (
            'attack_phase', 'mitre_tactic', 'mitre_technique')},
    }


# ---- auth.log parser ----
AUTH_PATTERNS = [
    (re.compile(r'sudo:\s+(\w+)\s*:.*COMMAND=(.+?)(?:\s+PWD=|\s+USER=|$)'), 'execution', 'sudo_execution'),
    (re.compile(r'pam_unix\(sudo:session\): session opened for user (\w+)'), 'execution', 'sudo_session'),
    (re.compile(r'sshd.*Accepted\s+\S+\s+for\s+(\w+)\s+from\s+([\d\.]+)'), 'authentication', 'login'),
    (re.compile(r'sshd.*Failed\s+\S+\s+for\s+(?:invalid user\s+)?(\w+)\s+from\s+([\d\.]+)'), 'authentication', 'failed_login'),
    (re.compile(r'pam_unix\(sshd:auth\):.*user=(\w+)'), 'authentication', 'auth_event'),
    (re.compile(r'pam_unix\(\w+:session\): session (opened|closed) for user (\w+)'), 'authentication', 'session'),
    (re.compile(r'useradd.*new user: name=(\w+)'), 'persistence', 'user_created'),
    (re.compile(r'passwd.*password changed for (\w+)'), 'persistence', 'password_changed'),
    (re.compile(r'CRON\[.+\]: \((\w+)\) CMD \((.+)\)'), 'execution', 'cron_job'),
]

def parse_auth_log(file_path: Path, participant_id, scenario_name, host) -> Iterator[dict]:
    year = None
    try:
        with open(file_path, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                # Detect year from file mtime
                if year is None:
                    try:
                        year = datetime.fromtimestamp(file_path.stat().st_mtime).year
                    except:
                        year = 2025

                # Parse timestamp: "Aug 15 12:00:00 hostname process[pid]: message"
                ts_str = ''
                m_ts = re.match(r'^(\w+\s+\d+\s+\d+:\d+:\d+)', line)
                if m_ts:
                    try:
                        ts = datetime.strptime(f"{m_ts.group(1)} {year}", "%b %d %H:%M:%S %Y")
                        ts_str = ts.isoformat()
                    except:
                        ts_str = m_ts.group(1)

                user = ''
                command = ''
                action_cat = 'system'
                action_name = 'auth_event'
                src_ip = ''

                for pat, cat, aname in AUTH_PATTERNS:
                    m = pat.search(line)
                    if m:
                        action_cat = cat
                        action_name = aname
                        groups = m.groups()
                        if aname == 'sudo_execution':
                            user = groups[0]
                            command = groups[1].strip()
                        elif aname == 'login' or aname == 'failed_login':
                            user = groups[0]
                            src_ip = groups[1] if len(groups) > 1 else ''
                        elif aname == 'session':
                            user = groups[1]
                        elif aname == 'cron_job':
                            user = groups[0]
                            command = groups[1].strip()
                        else:
                            user = groups[0] if groups else ''
                        break

                # Fallback user extraction
                if not user:
                    user = extract_user_from_raw(line)

                yield make_event(
                    participant_id, scenario_name, host, 'auth', file_path,
                    timestamp_utc=ts_str,
                    user=user,
                    action_category=action_cat,
                    action_name=action_name,
                    src_ip=src_ip,
                    command=command,
                    raw_data=line,
                )
    except Exception as e:
        logger.debug(f"auth parse error {file_path}: {e}")


# ---- bt.jsonl parser ----
BT_ACTION_MAP = {
    'docker': ('execution', 'docker_activity', 'docker'),
    'honey': ('detection', 'honeypot_activity', 'honeypot'),
    'rootkit': ('persistence', 'rootkit_activity', ''),
    'ssh': ('lateral_movement', 'ssh_activity', 'ssh'),
    'exec': ('execution', 'exec_activity', ''),
    'network': ('network', 'network_activity', ''),
}

def parse_bt_jsonl(file_path: Path, participant_id, scenario_name, host) -> Iterator[dict]:
    try:
        with open(file_path, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except:
                    continue

                ts_raw = data.get('timestamp', '')
                ts_str = ''
                if ts_raw:
                    try:
                        dt = datetime.fromisoformat(ts_raw.replace('Z', '+00:00'))
                        ts_str = dt.replace(tzinfo=None).isoformat()
                    except:
                        ts_str = ts_raw

                index = data.get('index', '').lower()
                message = data.get('message', '')
                level = int(data.get('level', data.get('loglevel', '0')) or 0)
                hostname = data.get('hostname', host)
                ipv4 = data.get('ipv4', '')
                source = data.get('source', index)

                # Determine action
                action_cat = 'behavior'
                action_name = 'behavior_event'
                tool = ''
                alert_type = ''
                alert_severity = 0

                for key, (cat, aname, t) in BT_ACTION_MAP.items():
                    if key in index or key in source.lower():
                        action_cat = cat
                        action_name = aname
                        tool = t
                        break

                if 'rootkit' in index:
                    alert_type = 'rootkit'
                    alert_severity = 7 if level == 1 else 5

                # Extract command from message
                command = ''
                # "Executing command: xxx" or "Running: xxx" etc
                cmd_m = re.search(r'(?:Executing|Running|Exec(?:ute)?|CMD|command)[:\s]+(.+?)(?:\s*$)', message, re.I)
                if cmd_m:
                    command = cmd_m.group(1).strip().strip('"\'')

                # Extract user from message
                user = ''
                u_m = re.search(r'(?:user|USER)\s*[=:]\s*(\w+)', message)
                if u_m:
                    user = u_m.group(1)

                result = 'failure' if ('error' in message.lower() or 'fail' in message.lower()) else 'success'

                yield make_event(
                    participant_id, scenario_name, hostname, 'bt_jsonl', file_path,
                    timestamp_utc=ts_str,
                    user=user,
                    action_category=action_cat,
                    action_name=action_name,
                    tool=tool,
                    command=command,
                    alert_type=alert_type,
                    alert_severity=alert_severity,
                    result=result,
                    src_ip=ipv4,
                    detection_source='behavior_tracking',
                    raw_data=json.dumps(data),
                )
    except Exception as e:
        logger.debug(f"bt.jsonl parse error {file_path}: {e}")


# ---- sensor.log parser ----
def parse_sensor_log(file_path: Path, participant_id, scenario_name, host) -> Iterator[dict]:
    try:
        with open(file_path, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('Sensing'):
                    continue
                # Python dict-like lines: {'time': ..., 'type': 'PACKET', 'data': {...}}
                if line.startswith("{'time'") or line.startswith('{"time"'):
                    try:
                        data = json.loads(line.replace("'", '"'))
                    except:
                        try:
                            import ast
                            data = ast.literal_eval(line)
                        except:
                            continue

                    ts_float = data.get('time', 0)
                    ts_str = ''
                    if ts_float:
                        try:
                            ts_str = datetime.utcfromtimestamp(ts_float).isoformat()
                        except:
                            pass

                    dtype = data.get('type', '')
                    pdata = data.get('data', {})

                    src_ip = pdata.get('src_ip', '')
                    dst_ip = pdata.get('dst_ip', '')
                    src_port = pdata.get('src_port', 0)
                    dst_port = pdata.get('dst_port', 0)
                    payload = pdata.get('payload', '')

                    action_name = 'sensor_packet'
                    action_cat = 'network'
                    tool = 'sensor'
                    command = ''
                    alert_type = ''
                    alert_sev = 0

                    if payload:
                        # HTTP in payload
                        if 'HTTP' in payload:
                            action_name = 'http_traffic'
                            m_http = re.search(r'(GET|POST|PUT|DELETE|HEAD)\s+(\S+)', payload)
                            if m_http:
                                command = f"{m_http.group(1)} {m_http.group(2)}"
                        elif 'SSH' in payload:
                            action_name = 'ssh_session'
                            tool = 'ssh'
                        elif 'ATTACK_STATUS' in payload or 'RTRIGGERD' in payload:
                            action_name = 'attack_status'
                            action_cat = 'behavior'
                            alert_type = 'attack_indicator'
                            alert_sev = 8

                    yield make_event(
                        participant_id, scenario_name, host, 'sensor', file_path,
                        timestamp_utc=ts_str,
                        action_category=action_cat,
                        action_name=action_name,
                        tool=tool,
                        command=command,
                        src_ip=src_ip,
                        dest_ip=dst_ip,
                        src_port=src_port,
                        dest_port=dst_port,
                        alert_type=alert_type,
                        alert_severity=alert_sev,
                        raw_data=line,
                    )

                # bt.jsonl-style (some sensor.log files have this format)
                elif line.startswith('{') and '"message"' in line:
                    try:
                        data = json.loads(line)
                        message = data.get('message', '')
                        ts_raw = data.get('timestamp', '')
                        ts_str = ''
                        if ts_raw:
                            try:
                                ts_str = datetime.fromisoformat(ts_raw.replace('Z', '+00:00')).replace(tzinfo=None).isoformat()
                            except:
                                ts_str = ts_raw

                        action_name = 'sensor_event'
                        alert_type = ''
                        alert_sev = 0

                        if 'ATTACK_STATUS' in message:
                            action_name = 'attack_status'
                            alert_type = 'attack_status'
                            alert_sev = 8
                        elif 'RTRIGGERD_QUERY' in message:
                            action_name = 'triggered_query'
                            alert_type = 'rootkit_trigger'
                            alert_sev = 7
                        elif 'SSHInterceptGetRules' in message:
                            action_name = 'ssh_intercept'
                            alert_type = 'ssh_intercept'
                            alert_sev = 6

                        yield make_event(
                            participant_id, scenario_name, host, 'sensor', file_path,
                            timestamp_utc=ts_str,
                            action_category='behavior',
                            action_name=action_name,
                            alert_type=alert_type,
                            alert_severity=alert_sev,
                            raw_data=line,
                        )
                    except:
                        pass
    except Exception as e:
        logger.debug(f"sensor parse error {file_path}: {e}")


# ---- syslog parser ----
SYSLOG_SERVICE_MAP = {
    'sshd': ('authentication', 'ssh_activity', 'ssh'),
    'sudo': ('execution', 'sudo_execution', 'sudo'),
    'CRON': ('execution', 'cron_job', 'cron'),
    'kernel': ('system', 'kernel_event', ''),
    'systemd': ('system', 'systemd_event', 'systemd'),
    'docker': ('execution', 'docker_activity', 'docker'),
    'NetworkManager': ('network', 'network_event', ''),
    'dnsmasq': ('network', 'dns_event', ''),
    'ufw': ('network', 'firewall_event', 'ufw'),
    'iptables': ('network', 'firewall_event', 'iptables'),
    'python': ('execution', 'python_execution', 'python'),
    'apache': ('web_access', 'http_request', 'apache'),
    'nginx': ('web_access', 'http_request', 'nginx'),
}

SYSLOG_TS_RE = re.compile(r'^(\w+\s+\d+\s+\d+:\d+:\d+)')
SYSLOG_LINE_RE = re.compile(r'^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)')

def parse_syslog(file_path: Path, participant_id, scenario_name, host) -> Iterator[dict]:
    try:
        year = None
        with open(file_path, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                if year is None:
                    try:
                        year = datetime.fromtimestamp(file_path.stat().st_mtime).year
                    except:
                        year = 2025

                m = SYSLOG_LINE_RE.match(line)
                if not m:
                    continue

                ts_raw, hostname, service, pid, message = m.groups()
                ts_str = ''
                try:
                    ts = datetime.strptime(f"{ts_raw} {year}", "%b %d %H:%M:%S %Y")
                    ts_str = ts.isoformat()
                except:
                    ts_str = ts_raw

                service_base = service.split('/')[0].split('-')[0]

                action_cat = 'system'
                action_name = 'syslog_event'
                tool = ''

                for svc, (cat, aname, t) in SYSLOG_SERVICE_MAP.items():
                    if svc.lower() in service.lower():
                        action_cat = cat
                        action_name = aname
                        tool = t
                        break

                # Extract user
                user = extract_user_from_raw(message) or extract_user_from_raw(line)
                # Extract command for sudo
                command = ''
                if 'sudo' in service.lower():
                    cmd_m = re.search(r'COMMAND=(.+?)(?:\s+PWD=|\s+USER=|$)', message)
                    if cmd_m:
                        command = cmd_m.group(1).strip()

                process_id = int(pid) if pid and pid.isdigit() else 0

                yield make_event(
                    participant_id, scenario_name, hostname or host, 'syslog', file_path,
                    timestamp_utc=ts_str,
                    user=user,
                    action_category=action_cat,
                    action_name=action_name,
                    tool=tool,
                    command=command,
                    process_id=process_id,
                    raw_data=line,
                )
    except Exception as e:
        logger.debug(f"syslog parse error {file_path}: {e}")


# ---- zeek conn.log parser ----
def parse_zeek_conn(file_path: Path, participant_id, scenario_name, host) -> Iterator[dict]:
    fields = []
    try:
        with open(file_path, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line.startswith('#fields'):
                    fields = line.split('\t')[1:]
                    continue
                if line.startswith('#') or not line:
                    continue
                if not fields:
                    continue
                parts = line.split('\t')
                row = dict(zip(fields, parts))

                ts_float = float(row.get('ts', 0) or 0)
                ts_str = datetime.utcfromtimestamp(ts_float).isoformat() if ts_float else ''

                src_ip = row.get('id.orig_h', '')
                src_port = int(row.get('id.orig_p', 0) or 0)
                dst_ip = row.get('id.resp_h', '')
                dst_port = int(row.get('id.resp_p', 0) or 0)
                proto = row.get('proto', '')
                service = row.get('service', '')
                duration = row.get('duration', '')
                conn_state = row.get('conn_state', '')

                action_name = 'flow'
                action_cat = 'network'
                tool = 'zeek'

                yield make_event(
                    participant_id, scenario_name, host, 'zeek', file_path,
                    timestamp_utc=ts_str,
                    action_category=action_cat,
                    action_name=action_name,
                    tool=tool,
                    src_ip=src_ip, src_port=src_port,
                    dest_ip=dst_ip, dest_port=dst_port,
                    protocol=proto,
                    raw_data=line,
                    extra_data=json.dumps({'service': service, 'duration': duration, 'conn_state': conn_state}),
                )
    except Exception as e:
        logger.debug(f"zeek conn parse error {file_path}: {e}")


def parse_zeek_http(file_path: Path, participant_id, scenario_name, host) -> Iterator[dict]:
    fields = []
    try:
        with open(file_path, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line.startswith('#fields'):
                    fields = line.split('\t')[1:]
                    continue
                if line.startswith('#') or not line:
                    continue
                if not fields:
                    continue
                parts = line.split('\t')
                row = dict(zip(fields, parts))

                ts_float = float(row.get('ts', 0) or 0)
                ts_str = datetime.utcfromtimestamp(ts_float).isoformat() if ts_float else ''

                yield make_event(
                    participant_id, scenario_name, host, 'zeek', file_path,
                    timestamp_utc=ts_str,
                    action_category='web_access',
                    action_name='http_request',
                    tool='zeek',
                    src_ip=row.get('id.orig_h', ''),
                    dest_ip=row.get('id.resp_h', ''),
                    dest_port=int(row.get('id.resp_p', 0) or 0),
                    http_method=row.get('method', ''),
                    url=row.get('uri', ''),
                    user_agent=row.get('user_agent', ''),
                    http_status=int(row.get('status_code', 0) or 0),
                    raw_data=line,
                )
    except Exception as e:
        logger.debug(f"zeek http parse error {file_path}: {e}")


def parse_zeek_ssh(file_path: Path, participant_id, scenario_name, host) -> Iterator[dict]:
    fields = []
    try:
        with open(file_path, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line.startswith('#fields'):
                    fields = line.split('\t')[1:]
                    continue
                if line.startswith('#') or not line:
                    continue
                if not fields:
                    continue
                parts = line.split('\t')
                row = dict(zip(fields, parts))

                ts_float = float(row.get('ts', 0) or 0)
                ts_str = datetime.utcfromtimestamp(ts_float).isoformat() if ts_float else ''
                auth_success = row.get('auth_success', '-')
                
                yield make_event(
                    participant_id, scenario_name, host, 'zeek', file_path,
                    timestamp_utc=ts_str,
                    action_category='authentication',
                    action_name='ssh_session',
                    tool='ssh',
                    src_ip=row.get('id.orig_h', ''),
                    dest_ip=row.get('id.resp_h', ''),
                    dest_port=int(row.get('id.resp_p', 22) or 22),
                    result='success' if auth_success == 'T' else 'failure',
                    raw_data=line,
                )
    except Exception as e:
        logger.debug(f"zeek ssh parse error {file_path}: {e}")


def parse_zeek_dns(file_path: Path, participant_id, scenario_name, host) -> Iterator[dict]:
    fields = []
    try:
        with open(file_path, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line.startswith('#fields'):
                    fields = line.split('\t')[1:]
                    continue
                if line.startswith('#') or not line:
                    continue
                if not fields:
                    continue
                parts = line.split('\t')
                row = dict(zip(fields, parts))

                ts_float = float(row.get('ts', 0) or 0)
                ts_str = datetime.utcfromtimestamp(ts_float).isoformat() if ts_float else ''
                query = row.get('query', '')
                qtype = row.get('qtype_name', '')

                yield make_event(
                    participant_id, scenario_name, host, 'zeek', file_path,
                    timestamp_utc=ts_str,
                    action_category='network',
                    action_name='dns_query',
                    tool='zeek',
                    src_ip=row.get('id.orig_h', ''),
                    command=f"DNS {qtype} {query}",
                    url=query,
                    raw_data=line,
                )
    except Exception as e:
        logger.debug(f"zeek dns parse error {file_path}: {e}")


# ---- Suricata EVE JSON ----
def parse_suricata_eve(file_path: Path, participant_id, scenario_name, host) -> Iterator[dict]:
    try:
        with open(file_path, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except:
                    continue

                ts_raw = data.get('timestamp', '')
                ts_str = ''
                if ts_raw:
                    try:
                        # Normalize compact UTC-offset notation (-0400 → -04:00) for
                        # Python < 3.11 which cannot parse offsets without the colon.
                        import re as _re
                        normalized = _re.sub(
                            r'([+-])(\d{2})(\d{2})$', r'\1\2:\3', ts_raw
                        )
                        ts_str = datetime.fromisoformat(normalized.replace('Z', '+00:00')).replace(tzinfo=None).isoformat()
                    except Exception:
                        ts_str = ts_raw

                etype = data.get('event_type', '')
                src_ip = data.get('src_ip', '')
                dest_ip = data.get('dest_ip', '')
                src_port = data.get('src_port', 0)
                dest_port = data.get('dest_port', 0)
                proto = data.get('proto', '')

                action_cat = 'network'
                action_name = f'suricata_{etype}' if etype else 'suricata_event'
                tool = 'suricata'
                alert_type = ''
                alert_sev = 0
                command = ''
                http_method = ''
                url = ''
                user_agent = ''
                http_status = 0

                if etype == 'alert':
                    alert_data = data.get('alert', {})
                    alert_type = alert_data.get('signature', '')
                    alert_sev = alert_data.get('severity', 0)
                    action_cat = 'detection'
                    action_name = 'ids_alert'
                    command = alert_type
                elif etype == 'http':
                    http_data = data.get('http', {})
                    http_method = http_data.get('http_method', '')
                    url = http_data.get('url', '')
                    user_agent = http_data.get('http_user_agent', '')
                    http_status = http_data.get('status', 0)
                    action_cat = 'web_access'
                    action_name = 'http_traffic'
                elif etype == 'ssh':
                    ssh_data = data.get('ssh', {})
                    action_cat = 'authentication'
                    action_name = 'suricata_ssh'
                elif etype == 'dns':
                    dns_data = data.get('dns', {})
                    query = dns_data.get('rrname', '')
                    command = f"DNS {query}"
                    action_cat = 'network'
                    action_name = 'dns_query'
                elif etype == 'fileinfo':
                    fi = data.get('fileinfo', {})
                    url = fi.get('filename', '')
                    action_cat = 'file_transfer'
                    action_name = 'file_detected'
                elif etype == 'flow':
                    action_cat = 'network'
                    action_name = 'flow'
                elif etype == 'stats':
                    action_cat = 'system'
                    action_name = 'ids_stats'

                yield make_event(
                    participant_id, scenario_name, host, 'suricata', file_path,
                    timestamp_utc=ts_str,
                    action_category=action_cat,
                    action_name=action_name,
                    tool=tool,
                    command=command,
                    src_ip=src_ip, src_port=src_port,
                    dest_ip=dest_ip, dest_port=dest_port,
                    protocol=proto,
                    alert_type=alert_type,
                    alert_severity=alert_sev,
                    http_method=http_method,
                    url=url,
                    user_agent=user_agent,
                    http_status=http_status,
                    raw_data=json.dumps(data),
                )
    except Exception as e:
        logger.debug(f"suricata parse error {file_path}: {e}")


# ---- Zeek notice.log parser ----
def parse_zeek_notice(file_path: Path, participant_id, scenario_name, host) -> Iterator[dict]:
    """Parse Zeek notice.log — IDS notices including port scan detections."""
    try:
        with open(file_path, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except:
                    continue

                ts_float = float(data.get('ts', 0) or 0)
                ts_str = datetime.utcfromtimestamp(ts_float).isoformat() if ts_float else ''

                note = data.get('note', '')
                msg = data.get('msg', '')
                src_ip = data.get('src', '')

                # Port scan detections are recon phase
                if 'Port_Scan' in note or 'Scan' in note:
                    action_cat = 'network'
                    action_name = 'port_scan_detected'
                    phase_override = 'recon'
                    tactic_override, technique_override = 'TA0043', 'T1046'
                elif 'CaptureLoss' in note:
                    action_cat = 'system'
                    action_name = 'capture_loss'
                    phase_override = 'defense_evasion'
                    tactic_override, technique_override = 'TA0005', 'T1562'
                else:
                    action_cat = 'detection'
                    action_name = 'ids_notice'
                    phase_override = 'discovery'
                    tactic_override, technique_override = 'TA0007', 'T1046'

                yield make_event(
                    participant_id, scenario_name, host, 'zeek', file_path,
                    timestamp_utc=ts_str,
                    action_category=action_cat,
                    action_name=action_name,
                    tool='zeek',
                    src_ip=src_ip,
                    command=msg,
                    attack_phase=phase_override,
                    mitre_tactic=tactic_override,
                    mitre_technique=technique_override,
                    raw_data=json.dumps(data),
                    extra_data=json.dumps({'note': note, 'msg': msg}),
                )
    except Exception as e:
        logger.debug(f"zeek notice parse error {file_path}: {e}")


# ---- Zeek files.log parser ----
def parse_zeek_files(file_path: Path, participant_id, scenario_name, host) -> Iterator[dict]:
    """Parse Zeek files.log — file transfers with MD5/SHA1/SHA256 hashes."""
    try:
        with open(file_path, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except:
                    continue

                ts_float = float(data.get('ts', 0) or 0)
                ts_str = datetime.utcfromtimestamp(ts_float).isoformat() if ts_float else ''

                src_ip = data.get('id.orig_h', '')
                src_port = int(data.get('id.orig_p', 0) or 0)
                dst_ip = data.get('id.resp_h', '')
                dst_port = int(data.get('id.resp_p', 0) or 0)
                mime_type = data.get('mime_type', '')
                seen_bytes = data.get('seen_bytes', 0)
                md5 = data.get('md5', '')
                sha1 = data.get('sha1', '')
                sha256 = data.get('sha256', '')
                filename = data.get('filename', '')
                source = data.get('source', '')

                cmd = filename or mime_type or f"file transfer via {source}"

                yield make_event(
                    participant_id, scenario_name, host, 'zeek', file_path,
                    timestamp_utc=ts_str,
                    action_category='file_transfer',
                    action_name='file_detected',
                    tool='zeek',
                    src_ip=src_ip, src_port=src_port,
                    dest_ip=dst_ip, dest_port=dst_port,
                    command=cmd,
                    attack_phase='collection',
                    mitre_tactic='TA0009',
                    mitre_technique='T1005',
                    raw_data=json.dumps(data),
                    extra_data=json.dumps({
                        'md5': md5, 'sha1': sha1, 'sha256': sha256,
                        'mime_type': mime_type, 'seen_bytes': seen_bytes,
                        'filename': filename, 'source': source,
                    }),
                )
    except Exception as e:
        logger.debug(f"zeek files parse error {file_path}: {e}")


# ---- Zeek weird.log parser ----
def parse_zeek_weird(file_path: Path, participant_id, scenario_name, host) -> Iterator[dict]:
    """Parse Zeek weird.log — network anomalies like bad checksums, truncated payloads."""
    try:
        with open(file_path, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except:
                    continue

                ts_float = float(data.get('ts', 0) or 0)
                ts_str = datetime.utcfromtimestamp(ts_float).isoformat() if ts_float else ''

                src_ip = data.get('id.orig_h', '')
                src_port = int(data.get('id.orig_p', 0) or 0)
                dst_ip = data.get('id.resp_h', '')
                dst_port = int(data.get('id.resp_p', 0) or 0)
                name = data.get('name', '')

                yield make_event(
                    participant_id, scenario_name, host, 'zeek', file_path,
                    timestamp_utc=ts_str,
                    action_category='network',
                    action_name='network_anomaly',
                    tool='zeek',
                    src_ip=src_ip, src_port=src_port,
                    dest_ip=dst_ip, dest_port=dst_port,
                    command=name,
                    raw_data=json.dumps(data),
                    extra_data=json.dumps({'anomaly': name}),
                )
    except Exception as e:
        logger.debug(f"zeek weird parse error {file_path}: {e}")


# ---- Suricata fast.log parser ----
# Format: MM/DD/YYYY-HH:MM:SS.ffffff  [**] [sid:rev] SIGNATURE [**] [Classification: X] [Priority: N] {PROTO} src:port -> dst:port
_FAST_RE = re.compile(
    r'^(\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)\s+'
    r'\[\*\*\] \[\d+:(\d+):\d+\] (.+?) \[\*\*\]'
    r'(?:\s+\[Classification: ([^\]]*)\])?'
    r'(?:\s+\[Priority: (\d+)\])?'
    r'\s+\{(\w+)\}\s+([\d\.]+):(\d+)\s+->\s+([\d\.]+):(\d+)'
)

def parse_suricata_fast(file_path: Path, participant_id, scenario_name, host) -> Iterator[dict]:
    """Parse Suricata fast.log — text-format IDS alerts."""
    try:
        with open(file_path, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                m = _FAST_RE.match(line)
                if not m:
                    continue

                ts_raw, sid, signature, classification, priority, proto, src_ip, src_port, dst_ip, dst_port = m.groups()

                try:
                    ts_str = datetime.strptime(ts_raw, '%m/%d/%Y-%H:%M:%S.%f').isoformat()
                except:
                    ts_str = ts_raw

                sev = int(priority) if priority else 0

                yield make_event(
                    participant_id, scenario_name, host, 'suricata', file_path,
                    timestamp_utc=ts_str,
                    action_category='detection',
                    action_name='ids_alert',
                    tool='suricata',
                    command=signature,
                    src_ip=src_ip,
                    src_port=int(src_port),
                    dest_ip=dst_ip,
                    dest_port=int(dst_port),
                    protocol=proto,
                    alert_type=signature,
                    alert_severity=sev,
                    raw_data=line,
                    extra_data=json.dumps({'sid': sid, 'classification': classification or '', 'priority': sev}),
                )
    except Exception as e:
        logger.debug(f"suricata fast parse error {file_path}: {e}")


# ---- UAT keylogger parser ----
def parse_uat(file_path: Path, participant_id, scenario_name, host) -> Iterator[dict]:
    # Get metadata from header
    user = ''
    uuid_val = ''
    hostname = host

    try:
        with open(file_path, 'r', errors='ignore') as f:
            for line in f:
                if line.startswith('# UUID:'):
                    uuid_val = line.split(':', 1)[1].strip()
                elif line.startswith('# Hostname:'):
                    hostname = line.split(':', 1)[1].strip()
                elif not line.startswith('#'):
                    break
    except:
        pass

    # Reconstruct typed commands
    typed_sessions = reconstruct_typed_text_from_uat(file_path)

    for session in typed_sessions:
        window = session.get('window', '')
        typed_text = session.get('typed_text', '')
        ts_str = session.get('timestamp', '')

        # Extract user from window title (e.g. "jvazquez@sec-admin-workstation-1: ~/.ssh")
        window_user = ''
        wm = re.match(r'^(\w+)@', window)
        if wm:
            window_user = wm.group(1)

        # Determine tool from window class/name
        tool = ''
        if 'terminal' in window.lower() or 'qterminal' in window.lower():
            tool = 'terminal'
        elif 'firefox' in window.lower():
            tool = 'firefox'
        elif 'chrome' in window.lower():
            tool = 'browser'
        elif 'thunar' in window.lower():
            tool = 'file_manager'
        elif 'text' in window.lower() or 'editor' in window.lower():
            tool = 'text_editor'
        else:
            tool = 'ui'

        command = typed_text if tool == 'terminal' else ''

        # UAT terminal input from attacker = reconnaissance; UI clicks = discovery
        if tool == 'terminal':
            phase_kw = {'attack_phase': 'reconnaissance', 'mitre_tactic': 'TA0043', 'mitre_technique': 'T1595'}
        else:
            phase_kw = {'attack_phase': 'discovery', 'mitre_tactic': 'TA0007', 'mitre_technique': 'T1046'}

        yield make_event(
            participant_id, scenario_name, hostname, 'uat', file_path,
            timestamp_utc=ts_str,
            user=window_user or user,
            action_category='execution' if tool == 'terminal' else 'ui_activity',
            action_name='terminal_input' if tool == 'terminal' else 'ui_activity',
            tool=tool,
            command=command,
            typed_text=typed_text,
            raw_data=f"window={window} text={typed_text}",
            **phase_kw,
        )


# ---- hacktools.log parser ----
def parse_hacktools(file_path: Path, participant_id, scenario_name, host) -> Iterator[dict]:
    # Apache-style: IP - - [date] "METHOD path HTTP/x.x" status -
    APACHE_RE = re.compile(
        r'([\d\.]+)\s+-\s+-\s+\[(.+?)\]\s+"(\w+)\s+(\S+)\s+HTTP/[\d\.]+"\s+(\d+)')
    try:
        with open(file_path, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                m = APACHE_RE.match(line)
                if m:
                    src_ip, date_str, method, url, status = m.groups()
                    ts_str = ''
                    try:
                        ts = datetime.strptime(date_str, "%d/%b/%Y %H:%M:%S")
                        ts_str = ts.isoformat()
                    except:
                        ts_str = date_str

                    # Determine if it's a tool download
                    tool_hint = ''
                    tool_keywords = ['exploit', 'metasploit', 'nmap', 'hydra', 'password', 'wordlist', 'cupp', 'CVE']
                    for kw in tool_keywords:
                        if kw.lower() in url.lower():
                            tool_hint = kw.lower()
                            break

                    yield make_event(
                        participant_id, scenario_name, host, 'hacktools', file_path,
                        timestamp_utc=ts_str,
                        action_category='tool_download',
                        action_name='tool_accessed',
                        tool=tool_hint or 'web',
                        src_ip=src_ip,
                        http_method=method,
                        url=url,
                        http_status=int(status),
                        command=f"{method} {url}",
                        raw_data=line,
                    )
    except Exception as e:
        logger.debug(f"hacktools parse error {file_path}: {e}")


def parse_apt_log(file_path: Path, participant_id, scenario_name, host) -> Iterator[dict]:
    """
    Parse Apache-style APT repository server logs.
    These logs record victim hosts downloading packages from the attacker-controlled
    APT mirror — a key indicator of tool delivery / initial_access / execution spread.

    Format: IP - - [DD/Mon/YYYY HH:MM:SS] "METHOD /path HTTP/x.x" status -

    Key distinctions:
    - .deb downloads -> execution (tool delivery to victim)
    - /key.asc, /dists/, /Packages -> initial_access (victim trusting repo)
    - 200 = success, 304 = cached, 4xx/5xx = failure
    """
    APACHE_RE = re.compile(
        r'([\d\.]+)\s+-\s+-\s+\[(.+?)\]\s+"(\w+)\s+(\S+)\s+HTTP/[\d\.]+"\s+(\d+)')

    # Tool name extraction from .deb paths
    DEB_RE = re.compile(r'/pool/[^/]+/[^/]+/[^/]+/([^_/]+)_')

    try:
        with open(file_path, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                m = APACHE_RE.match(line)
                if not m:
                    continue

                src_ip, date_str, method, url, status = m.groups()
                status_int = int(status)

                # Parse timestamp
                ts_str = date_str
                try:
                    ts = datetime.strptime(date_str, "%d/%b/%Y %H:%M:%S")
                    ts_str = ts.isoformat()
                except Exception:
                    pass

                url_lower = url.lower()

                # Classify request type
                if url_lower.endswith('.deb'):
                    # Package download — attacker tool delivered to victim
                    deb_m = DEB_RE.search(url)
                    tool_name = deb_m.group(1) if deb_m else 'package'
                    action_cat = 'execution'
                    action = 'package_download'
                    phase, tactic, technique = 'execution', 'TA0002', 'T1072'
                elif url_lower.endswith('.asc') or 'key' in url_lower:
                    # GPG key fetch — victim trusting attacker repo
                    tool_name = 'apt-key'
                    action_cat = 'initial_access'
                    action = 'repo_key_fetch'
                    phase, tactic, technique = 'initial_access', 'TA0001', 'T1195'
                elif '/dists/' in url_lower or '/packages' in url_lower.lower():
                    # Metadata/index fetch
                    tool_name = 'apt'
                    action_cat = 'initial_access'
                    action = 'repo_index_fetch'
                    phase, tactic, technique = 'initial_access', 'TA0001', 'T1195'
                else:
                    tool_name = 'apt'
                    action_cat = 'initial_access'
                    action = 'repo_request'
                    phase, tactic, technique = 'initial_access', 'TA0001', 'T1195'

                # Skip failed requests (keep 200, 304 etc but skip 4xx/5xx)
                if status_int >= 400:
                    continue

                yield make_event(
                    participant_id, scenario_name, host, 'apt_repo', file_path,
                    timestamp_utc=ts_str,
                    action_category=action_cat,
                    action_name=action,
                    tool=tool_name,
                    src_ip=src_ip,
                    http_method=method,
                    url=url,
                    http_status=status_int,
                    attack_phase=phase,
                    mitre_tactic=tactic,
                    mitre_technique=technique,
                    command=f"{method} {url}",
                    raw_data=line,
                )
    except Exception as e:
        logger.debug(f"apt_log parse error {file_path}: {e}")


# ---- .cast terminal recording ----
def parse_cast(file_path: Path, participant_id, scenario_name, host) -> Iterator[dict]:
    commands = extract_commands_from_cast(file_path)
    user = 'attacker'  # cast files are always from atkr-kali

    for cmd_entry in commands:
        ts_str = cmd_entry.get('timestamp', '')
        command = cmd_entry.get('command', '')
        if not command:
            continue

        yield make_event(
            participant_id, scenario_name, host, 'terminal_recording', file_path,
            timestamp_utc=ts_str,
            user=user,
            action_category='execution',
            action_name='terminal_command',
            tool='terminal',
            command=command,
            raw_data=command,
        )


# ---------------------------------------------------------------------------
# Main ingestion engine
# ---------------------------------------------------------------------------
PARSER_DISPATCH = {
    'auth.log': parse_auth_log,
    'bt.jsonl': parse_bt_jsonl,
    'sensor.log': parse_sensor_log,
    'syslog': parse_syslog,
    'eve.json': parse_suricata_eve,
    'hacktools.log': parse_hacktools,
    'fast.log': parse_suricata_fast,
}

ZEEK_DISPATCH = {
    'conn.log': parse_zeek_conn,
    'http.log': parse_zeek_http,
    'ssh.log': parse_zeek_ssh,
    'dns.log': parse_zeek_dns,
    'notice.log': parse_zeek_notice,
    'files.log': parse_zeek_files,
    'weird.log': parse_zeek_weird,
 }


def ingest_all(data_root: Path, db: DBv2):
    total = 0
    file_count = 0

    all_files = list(data_root.rglob('*'))
    logger.info(f"Found {len(all_files)} paths under {data_root}")

    for file_path in sorted(all_files):
        if not file_path.is_file():
            continue

        participant_id, scenario_name, host = parse_path_meta(file_path)
        fname = file_path.name

        # Skip binary / large files
        if fname.endswith('.pcap') or fname.endswith('.ogv') or fname.endswith('.webm') or fname.endswith('.log.pcap'):
            # Register as media event
            db.insert(make_event(
                participant_id, scenario_name, host, 'media', file_path,
                action_category='media',
                action_name='video_recording' if fname.endswith('.ogv') else 'network_capture',
                tool='pcap' if fname.endswith('.pcap') else 'video',
                raw_data=str(file_path),
            ))
            total += 1
            continue

        # Cast files
        if fname.endswith('.cast'):
            events = parse_cast(file_path, participant_id, scenario_name, host)
            for e in events:
                db.insert(e)
                total += 1
            file_count += 1
            logger.debug(f"cast: {file_path.name} -> {total} total")
            continue

        # UAT files — all variants including log-rotated (.tsv, .tsv.1, .tsv.2, ...)
        if re.match(r'UAT-.+\.tsv(\.\d+)?$', fname):
            events = parse_uat(file_path, participant_id, scenario_name, host)
            for e in events:
                db.insert(e)
                total += 1
            file_count += 1
            continue

        # Known parsers
        if fname in PARSER_DISPATCH:
            parser_fn = PARSER_DISPATCH[fname]
            # Determine if zeek directory
            if file_path.parent.name == 'zeek' and fname in ZEEK_DISPATCH:
                parser_fn = ZEEK_DISPATCH[fname]
            events = parser_fn(file_path, participant_id, scenario_name, host)
            for e in events:
                db.insert(e)
                total += 1
            file_count += 1
            if file_count % 20 == 0:
                logger.info(f"  Progress: {file_count} files, {total} events ...")
            continue

        # Zeek logs
        if file_path.parent.name == 'zeek' and fname in ZEEK_DISPATCH:
            events = ZEEK_DISPATCH[fname](file_path, participant_id, scenario_name, host)
            for e in events:
                db.insert(e)
                total += 1
            file_count += 1
            continue

        # apt.log (attacker APT repo server — apache access log style)
        if fname == 'apt.log':
            events = parse_apt_log(file_path, participant_id, scenario_name, host)
            for e in events:
                db.insert(e)
                total += 1
            file_count += 1
            continue

        # bt.log (text format companion to bt.jsonl)
        if fname == 'bt.log':
            # Parse as syslog-like
            events = parse_syslog(file_path, participant_id, scenario_name, host)
            for e in events:
                db.insert(e)
                total += 1
            file_count += 1
            continue

    db.flush()
    return total, file_count


if __name__ == '__main__':
    logger.info("GOD EYE V2 - Full Re-ingestion")
    logger.info(f"Data root: {DATA_ROOT}")
    logger.info(f"Database: {DB_PATH}")

    if DB_PATH.exists():
        logger.info("Removing existing v2 database...")
        DB_PATH.unlink()

    db = DBv2(DB_PATH)

    try:
        total_events, total_files = ingest_all(DATA_ROOT, db)
        logger.info(f"Ingestion complete: {total_events} events from {total_files} files")
    finally:
        db.close()

    # Print summary stats
    db2 = DBv2(DB_PATH)
    stats = db2.query("SELECT COUNT(*) as n FROM events")[0]['n']
    phases = db2.query("SELECT attack_phase, COUNT(*) as n FROM events GROUP BY attack_phase ORDER BY n DESC")
    participants = db2.query("SELECT participant_id, COUNT(*) as n FROM events GROUP BY participant_id ORDER BY n DESC")
    commands = db2.query("SELECT COUNT(*) as n FROM events WHERE command != '' AND command IS NOT NULL")[0]['n']
    users = db2.query("SELECT user, COUNT(*) as n FROM events WHERE user != '' AND user IS NOT NULL GROUP BY user ORDER BY n DESC LIMIT 15")
    typed = db2.query("SELECT COUNT(*) as n FROM events WHERE typed_text != '' AND typed_text IS NOT NULL")[0]['n']

    print(f"\n{'='*60}")
    print(f"GOD EYE V2 DATABASE SUMMARY")
    print(f"{'='*60}")
    print(f"Total events   : {stats:,}")
    print(f"With commands  : {commands:,}")
    print(f"With typed_text: {typed:,}")
    print(f"\nBy participant:")
    for p in participants:
        print(f"  {p['participant_id']:20s}: {p['n']:,}")
    print(f"\nBy attack phase:")
    for ph in phases:
        print(f"  {(ph['attack_phase'] or 'unknown'):25s}: {ph['n']:,}")
    print(f"\nTop users:")
    for u in users:
        print(f"  {u['user']:20s}: {u['n']:,}")
    db2.close()
