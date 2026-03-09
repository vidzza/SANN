"""
OBSIDIAN - Auth Log Parser
Parser for auth.log files
"""

import re
import logging
from pathlib import Path
from typing import Iterator, Optional
from datetime import datetime

from parsers.base import BaseParser, ParsedEvent

logger = logging.getLogger(__name__)

class AuthParser(BaseParser):
    """
    Parser for auth.log files
    
    Example:
    Jul 20 14:00:31 dmz-hp sudo: root : TTY=unknown ; PWD=/tmp/.docker_process_803988805 ; USER=root ; COMMAND=/usr/bin/docker compose up --detach
    Jul 20 14:00:31 dmz-hp pam_unix(sudo:session): session opened for user root by (uid=0)
    """
    
    # Patterns for auth.log entries
    SUDO_PATTERN = re.compile(
        r'^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+'
        r'(?P<host>\S+)\s+sudo:\s+'
        r'(?P<user>\S+)\s+'
        r'(?:TTY=(?P<tty>\S+)\s+;?\s*)?'
        r'(?:PWD=(?P<pwd>\S+)\s+;?\s*)?'
        r'(?:USER=(?P<target_user>\S+)\s+;?\s*)?'
        r'(?:COMMAND=(?P<command>.+))?'
    )
    
    SESSION_PATTERN = re.compile(
        r'^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+'
        r'(?P<host>\S+)\s+'
        r'pam_unix\((?P<service>\S+)\):\s+'
        r'(?P<action>session\s+opened|session\s+closed)\s+'
        r'for\s+user\s+(?P<user>\S+)'
    )
    
    LOGIN_PATTERN = re.compile(
        r'^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+'
        r'(?P<host>\S+)\s+'
        r'(?P<service>\S+)\[(?P<pid>\d+)\]:\s+'
        r'(?P<action>Accepted|Failed|Bad)\s+(?P<auth_method>\S+)\s+'
        r'for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)'
    )
    
    def can_parse(self, file_path: Path) -> bool:
        """Check if this is an auth.log file"""
        return file_path.name == 'auth.log'
    
    def parse(self, file_path: Path) -> Iterator[ParsedEvent]:
        """Parse auth.log file"""
        source_host = self.extract_host_from_path(file_path)
        scenario_id = self.extract_scenario_from_path(file_path)
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    event = None
                    
                    # Try sudo pattern
                    match = self.SUDO_PATTERN.match(line)
                    if match:
                        event = self._parse_sudo(match.groupdict(), line, source_host, scenario_id)
                    
                    # Try session pattern
                    if not event:
                        match = self.SESSION_PATTERN.match(line)
                        if match:
                            event = self._parse_session(match.groupdict(), line, source_host, scenario_id)
                    
                    # Try login pattern
                    if not event:
                        match = self.LOGIN_PATTERN.match(line)
                        if match:
                            event = self._parse_login(match.groupdict(), line, source_host, scenario_id)
                    
                    if event:
                        self.events_parsed += 1
                        yield event
                    else:
                        # Try generic parsing
                        event = self._parse_generic(line, source_host, scenario_id)
                        if event:
                            self.events_parsed += 1
                            yield event
                            
        except Exception as e:
            self.errors += 1
            logger.error(f"Error opening auth.log file {file_path}: {e}")
    
    def _parse_sudo(self, groups: dict, line: str, source_host: str, scenario_id: str) -> ParsedEvent:
        """Parse sudo command entry"""
        
        timestamp = self._build_timestamp(groups.get('month'), groups.get('day'), groups.get('time'))
        
        user = groups.get('user', '')
        command = groups.get('command', '')
        tty = groups.get('tty', '')
        pwd = groups.get('pwd', '')
        target_user = groups.get('target_user', '')
        
        # Detect tool from command
        tool = self._detect_tool_from_command(command)
        
        # Determine result
        result = 'success'
        if command:
            result = 'success'
        
        event = ParsedEvent(
            source_type='auth',
            source_file='',
            source_host=source_host or groups.get('host', ''),
            scenario_id=scenario_id,
            timestamp_utc=timestamp,
            user=user,
            tty=tty,
            working_dir=pwd,
            command=command,
            tool=tool,
            action_category='authentication',
            action_name='sudo_execution',
            result=result,
            raw_data=line,
            parsed_data={
                'target_user': target_user,
                'tty': tty,
                'working_dir': pwd
            }
        )
        
        # Set network info if command contains SSH
        if command and 'ssh' in command.lower():
            ssh_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', command)
            if ssh_match:
                event.dest_ip = ssh_match.group(1)
        
        return event
    
    def _parse_session(self, groups: dict, line: str, source_host: str, scenario_id: str) -> ParsedEvent:
        """Parse session open/close entry"""
        
        timestamp = self._build_timestamp(groups.get('month'), groups.get('day'), groups.get('time'))
        
        action = groups.get('action', '')
        user = groups.get('user', '')
        service = groups.get('service', '')
        
        event = ParsedEvent(
            source_type='auth',
            source_file='',
            source_host=source_host or groups.get('host', ''),
            scenario_id=scenario_id,
            timestamp_utc=timestamp,
            user=user,
            action_category='session',
            action_name='session_opened' if 'opened' in action else 'session_closed',
            result='success',
            session_id=f"{user}-{service}",
            raw_data=line,
            parsed_data={
                'service': service
            }
        )
        
        return event
    
    def _parse_login(self, groups: dict, line: str, source_host: str, scenario_id: str) -> ParsedEvent:
        """Parse login attempt entry"""
        
        timestamp = self._build_timestamp(groups.get('month'), groups.get('day'), groups.get('time'))
        
        action = groups.get('action', '')
        user = groups.get('user', '')
        ip = groups.get('ip', '')
        
        result = 'success' if action == 'Accepted' else 'failure'
        
        event = ParsedEvent(
            source_type='auth',
            source_file='',
            source_host=source_host or groups.get('host', ''),
            scenario_id=scenario_id,
            timestamp_utc=timestamp,
            user=user,
            action_category='authentication',
            action_name='login',
            result=result,
            dest_ip=ip if ip and ip != 'UNKNOWN' else '',
            raw_data=line,
            parsed_data={
                'auth_method': groups.get('auth_method', ''),
                'ip': ip
            }
        )
        
        return event
    
    def _parse_generic(self, line: str, source_host: str, scenario_id: str) -> Optional[ParsedEvent]:
        """Generic fallback parser"""
        
        # Try to extract basic info
        parts = line.split()
        if len(parts) >= 4:
            return ParsedEvent(
                source_type='auth',
                source_file='',
                source_host=source_host,
                scenario_id=scenario_id,
                timestamp_utc=None,
                action_category='system',
                action_name='auth_event',
                raw_data=line
            )
        
        return None
    
    def _build_timestamp(self, month: str, day: str, time: str) -> Optional[datetime]:
        """Build timestamp from month/day/time"""
        if not month or not day or not time:
            return None
            
        try:
            # Use current year as default
            year = datetime.now().year
            timestamp_str = f"{year} {month} {day} {time}"
            return datetime.strptime(timestamp_str, "%Y %b %d %H:%M:%S")
        except:
            return None
    
    def _detect_tool_from_command(self, command: str) -> str:
        """Detect security tool from command"""
        if not command:
            return ''
        
        command_lower = command.lower()
        
        tools = [
            'nmap', 'nikto', 'sqlmap', 'hydra', 'msfconsole', 'metasploit',
            'gobuster', 'dirb', 'ffuf', 'feroxbuster', 'wpscan',
            'nc', 'netcat', 'socat', 'curl', 'wget',
            'john', 'hashcat', 'aircrack', 'responder', 'impacket',
            'linpeas', 'linenum', 'pspy',
            'docker', 'docker-compose', 'kubectl',
            'python', 'python3', 'perl', 'ruby', 'php',
            'bash', 'sh', 'zsh',
            'ssh', 'scp', 'sftp', 'ftp', 'telnet',
            'mysql', 'psql', 'mongosh', 'redis-cli',
            'git', 'svn', 'wget', 'curl',
        ]
        
        for tool in tools:
            if tool in command_lower:
                return tool
        
        # Check for common attack patterns
        if 'sudo' in command_lower:
            return 'sudo'
        if 'su ' in command_lower:
            return 'su'
            
        return 'unknown'
