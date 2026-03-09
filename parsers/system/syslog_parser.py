"""
OBSIDIAN - Syslog Parser
Parser for syslog files
"""

import re
import logging
from pathlib import Path
from typing import Iterator
from datetime import datetime

from parsers.base import BaseParser, ParsedEvent

logger = logging.getLogger(__name__)

class SyslogParser(BaseParser):
    """
    Parser for syslog files
    
    Example:
    Jul 20 14:00:31 dmz-hp systemd[1]: Started Docker Application Container Engine.
    """
    
    def can_parse(self, file_path: Path) -> bool:
        """Check if this is a syslog file"""
        return file_path.name == 'syslog'
    
    def parse(self, file_path: Path) -> Iterator[ParsedEvent]:
        """Parse syslog file"""
        source_host = self.extract_host_from_path(file_path)
        scenario_id = self.extract_scenario_from_path(file_path)
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        event = self._parse_line(line, source_host, scenario_id, file_path)
                        if event:
                            self.events_parsed += 1
                            yield event
                    except Exception as e:
                        self.errors += 1
                        logger.debug(f"Error parsing line {line_num}: {e}")
                        
        except Exception as e:
            self.errors += 1
            logger.error(f"Error opening syslog file {file_path}: {e}")
    
    def _parse_line(self, line: str, source_host: str, scenario_id: str, file_path: Path) -> ParsedEvent:
        """Parse a single syslog line"""
        
        # Basic syslog format: Month Day Time Host Process[PID]: Message
        pattern = re.compile(
            r'^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+'
            r'(?P<host>\S+)\s+'
            r'(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s*'
            r'(?P<message>.*)'
        )
        
        match = pattern.match(line)
        
        if match:
            groups = match.groupdict()
            timestamp = self._build_timestamp(groups.get('month'), groups.get('day'), groups.get('time'))
            process = groups.get('process', '')
            pid = groups.get('pid', '0')
            message = groups.get('message', '')
            
            # Determine action from process and message
            action_name, action_category, tool = self._classify_event(process, message)
            
            event = ParsedEvent(
                source_type='syslog',
                source_file=str(file_path),
                source_host=source_host or groups.get('host', ''),
                scenario_id=scenario_id,
                timestamp_utc=timestamp,
                action_name=action_name,
                action_category=action_category,
                tool=tool,
                process_id=int(pid) if pid and pid.isdigit() else 0,
                raw_data=line,
                parsed_data={
                    'process': process,
                    'message': message
                }
            )
            
            # Try to extract network info
            ip_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+)')
            ip_matches = ip_pattern.findall(message)
            if ip_matches:
                event.dest_ip = ip_matches[0]
            
            return event
        
        # Fallback for non-matching lines
        return ParsedEvent(
            source_type='syslog',
            source_file=str(file_path),
            source_host=source_host,
            scenario_id=scenario_id,
            action_name='syslog_event',
            action_category='system',
            raw_data=line
        )
    
    def _classify_event(self, process: str, message: str) -> tuple:
        """Classify syslog event"""
        process_lower = process.lower()
        message_lower = message.lower()
        
        # Docker
        if 'docker' in process_lower:
            return ('docker_event', 'execution', 'docker')
        
        # SSH
        if 'sshd' in process_lower:
            if 'accepted' in message_lower:
                return ('ssh_login', 'authentication', 'ssh')
            elif 'failed' in message_lower:
                return ('ssh_failed', 'authentication', 'ssh')
            return ('ssh_event', 'authentication', 'ssh')
        
        # systemd
        if process_lower == 'systemd':
            if 'started' in message_lower:
                return ('service_started', 'system', 'systemd')
            elif 'stopped' in message_lower:
                return ('service_stopped', 'system', 'systemd')
            elif 'starting' in message_lower:
                return ('service_starting', 'system', 'systemd')
        
        # Network
        if 'network' in process_lower or 'dhcp' in process_lower:
            return ('network_event', 'network', 'network')
        
        # Kernel
        if process_lower == 'kernel':
            return ('kernel_event', 'system', 'kernel')
        
        # Cron
        if 'cron' in process_lower:
            return ('cron_event', 'scheduled', 'cron')
        
        # Default
        return ('syslog_event', 'system', process_lower if process_lower else 'unknown')
    
    def _build_timestamp(self, month: str, day: str, time: str) -> datetime:
        """Build timestamp from month/day/time"""
        try:
            year = datetime.now().year
            timestamp_str = f"{year} {month} {day} {time}"
            return datetime.strptime(timestamp_str, "%Y %b %d %H:%M:%S")
        except:
            return datetime.now()
