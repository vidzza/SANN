"""
OBSIDIAN - Zeek Network Logs Parser
Parser for Zeek log files (conn.log, ssh.log, dns.log, http.log, notice.log, etc.)
"""

import json
import logging
from pathlib import Path
from typing import Iterator, Dict, Any
from datetime import datetime

from parsers.base import BaseParser, ParsedEvent

logger = logging.getLogger(__name__)

class ZeekParser(BaseParser):
    """
    Parser for Zeek network logs
    
    Handles:
    - conn.log: Network connections
    - ssh.log: SSH sessions
    - dns.log: DNS queries
    - http.log: HTTP traffic
    - notice.log: Security alerts
    - files.log: File transfers
    """
    
    ZEEK_LOG_TYPES = {
        'conn.log': 'connection',
        'ssh.log': 'ssh',
        'dns.log': 'dns',
        'http.log': 'http',
        'notice.log': 'notice',
        'files.log': 'files',
        'dhcp.log': 'dhcp',
        'ssl.log': 'ssl',
    }
    
    def can_parse(self, file_path: Path) -> bool:
        """Check if this is a Zeek log file"""
        parent = file_path.parent.name
        filename = file_path.name
        return parent == 'zeek' and filename in self.ZEEK_LOG_TYPES
    
    def parse(self, file_path: Path) -> Iterator[ParsedEvent]:
        """Parse Zeek log file"""
        source_host = self.extract_host_from_path(file_path)
        scenario_id = self.extract_scenario_from_path(file_path)
        
        log_type = self.ZEEK_LOG_TYPES.get(file_path.name, 'unknown')
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Skip header comments
                for line in f:
                    if not line.startswith('#'):
                        break
                
                # Parse log entries
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        event = self._parse_line(line, log_type, source_host, scenario_id, file_path)
                        if event:
                            self.events_parsed += 1
                            yield event
                    except Exception as e:
                        self.errors += 1
                        logger.debug(f"Error parsing Zeek line {line_num}: {e}")
                        
        except Exception as e:
            self.errors += 1
            logger.error(f"Error opening Zeek log {file_path}: {e}")
    
    def _parse_line(self, line: str, log_type: str, source_host: str, scenario_id: str, file_path: Path) -> ParsedEvent:
        """Parse a single Zeek log line (JSON format)"""
        
        # Zeek JSON format
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            # Fallback to tab-separated
            fields = line.split('\t')
            data = {}
            # This would need field mapping - simplified for now
            return ParsedEvent(
                source_type='zeek',
                source_file=str(file_path),
                source_host=source_host,
                scenario_id=scenario_id,
                raw_data=line
            )
        
        # Parse based on log type
        if log_type == 'connection':
            return self._parse_connection(data, source_host, scenario_id, file_path)
        elif log_type == 'ssh':
            return self._parse_ssh(data, source_host, scenario_id, file_path)
        elif log_type == 'dns':
            return self._parse_dns(data, source_host, scenario_id, file_path)
        elif log_type == 'http':
            return self._parse_http(data, source_host, scenario_id, file_path)
        elif log_type == 'notice':
            return self._parse_notice(data, source_host, scenario_id, file_path)
        elif log_type == 'files':
            return self._parse_files(data, source_host, scenario_id, file_path)
        else:
            return self._parse_generic(data, source_host, scenario_id, file_path)
    
    def _parse_connection(self, data: Dict, source_host: str, scenario_id: str, file_path: Path) -> ParsedEvent:
        """Parse Zeek connection log (conn.log)"""
        
        timestamp = self._parse_timestamp_zeek(data.get('ts'))
        
        event = ParsedEvent(
            source_type='zeek',
            source_file=str(file_path),
            source_host=source_host,
            scenario_id=scenario_id,
            timestamp_utc=timestamp,
            action_category='network',
            action_name='network_connection',
            protocol=data.get('proto', '').lower(),
            network_uid=data.get('uid', ''),
            src_ip=data.get('id.orig_h', ''),
            src_port=int(data.get('id.orig_p', 0)),
            dest_ip=data.get('id.resp_h', ''),
            dest_port=int(data.get('id.resp_p', 0)),
            result=self._map_conn_state(data.get('conn_state', '')),
            raw_data=json.dumps(data),
            parsed_data=data
        )
        
        # Calculate duration and bytes
        duration = data.get('duration', 0)
        if duration:
            event.parsed_data['duration_seconds'] = duration
        
        orig_bytes = data.get('orig_bytes', 0)
        resp_bytes = data.get('resp_bytes', 0)
        if orig_bytes or resp_bytes:
            event.parsed_data['bytes_transferred'] = orig_bytes + resp_bytes
        
        return event
    
    def _parse_ssh(self, data: Dict, source_host: str, scenario_id: str, file_path: Path) -> ParsedEvent:
        """Parse Zeek SSH log"""
        
        timestamp = self._parse_timestamp_zeek(data.get('ts'))
        
        # Map auth success
        auth_success = None
        auth_attempts = 0
        if 'auth_success' in data:
            auth_success = data.get('auth_success', False)
        if 'auth_attempts' in data:
            auth_attempts = int(data.get('auth_attempts', 0))
        
        event = ParsedEvent(
            source_type='zeek',
            source_file=str(file_path),
            source_host=source_host,
            scenario_id=scenario_id,
            timestamp_utc=timestamp,
            action_category='authentication',
            action_name='ssh_session',
            protocol='ssh',
            network_uid=data.get('uid', ''),
            src_ip=data.get('id.orig_h', ''),
            src_port=int(data.get('id.orig_p', 0)),
            dest_ip=data.get('id.resp_h', ''),
            dest_port=int(data.get('id.resp_p', 22)),
            ssh_client=data.get('client', ''),
            ssh_server=data.get('server', ''),
            ssh_version=data.get('version', ''),
            auth_success=auth_success,
            auth_attempts=auth_attempts,
            result='success' if auth_success else 'failure',
            raw_data=json.dumps(data),
            parsed_data=data
        )
        
        # Extract user if available
        if 'user' in data:
            event.user = data.get('user', '')
        
        # Add hassh fingerprints if available
        if 'hassh' in data:
            event.parsed_data['hassh'] = data.get('hassh', '')
        if 'hasshServer' in data:
            event.parsed_data['hasshServer'] = data.get('hasshServer', '')
        
        return event
    
    def _parse_dns(self, data: Dict, source_host: str, scenario_id: str, file_path: Path) -> ParsedEvent:
        """Parse Zeek DNS log"""
        
        timestamp = self._parse_timestamp_zeek(data.get('ts'))
        
        query = data.get('query', '')
        qtype = data.get('qtype', '')
        
        event = ParsedEvent(
            source_type='zeek',
            source_file=str(file_path),
            source_host=source_host,
            scenario_id=scenario_id,
            timestamp_utc=timestamp,
            action_category='network',
            action_name='dns_query',
            protocol='dns',
            network_uid=data.get('uid', ''),
            src_ip=data.get('id.orig_h', ''),
            dest_ip=data.get('id.resp_h', ''),
            dest_port=53,
            url=query,  # Use query as URL for DNS
            raw_data=json.dumps(data),
            parsed_data={
                'query': query,
                'qtype': qtype,
                'rcode': data.get('rcode', ''),
                'answers': data.get('answers', [])
            }
        )
        
        return event
    
    def _parse_http(self, data: Dict, source_host: str, scenario_id: str, file_path: Path) -> ParsedEvent:
        """Parse Zeek HTTP log"""
        
        timestamp = self._parse_timestamp_zeek(data.get('ts'))
        
        event = ParsedEvent(
            source_type='zeek',
            source_file=str(file_path),
            source_host=source_host,
            scenario_id=scenario_id,
            timestamp_utc=timestamp,
            action_category='network',
            action_name='http_request',
            protocol='http',
            network_uid=data.get('uid', ''),
            src_ip=data.get('id.orig_h', ''),
            src_port=int(data.get('id.orig_p', 0)),
            dest_ip=data.get('id.resp_h', ''),
            dest_port=int(data.get('id.resp_p', 80)),
            http_method=data.get('method', ''),
            url=data.get('uri', ''),
            user_agent=data.get('user_agent', ''),
            http_status=int(data.get('status_code', 0)) if data.get('status_code') else 0,
            result='success' if int(data.get('status_code', 0)) < 400 else 'failure',
            raw_data=json.dumps(data),
            parsed_data=data
        )
        
        return event
    
    def _parse_notice(self, data: Dict, source_host: str, scenario_id: str, file_path: Path) -> ParsedEvent:
        """Parse Zeek notice log (security alerts)"""
        
        timestamp = self._parse_timestamp_zeek(data.get('ts'))
        
        note = data.get('note', '')
        msg = data.get('msg', '')
        
        # Classify alert
        alert_type = ''
        alert_severity = 5
        
        if 'Port_Scan' in note:
            alert_type = 'port_scan'
            alert_severity = 7
        elif 'Password_Guessing' in note:
            alert_type = 'password_guessing'
            alert_severity = 8
        elif 'Malware' in note:
            alert_type = 'malware'
            alert_severity = 10
        elif 'CaptureLoss' in note:
            alert_type = 'capture_loss'
            alert_severity = 3
        
        event = ParsedEvent(
            source_type='zeek',
            source_file=str(file_path),
            source_host=source_host,
            scenario_id=scenario_id,
            timestamp_utc=timestamp,
            action_category='detection',
            action_name='security_alert',
            alert_type=alert_type,
            alert_severity=alert_severity,
            detection_source='zeek',
            src_ip=data.get('src', ''),
            result='alert',
            raw_data=json.dumps(data),
            parsed_data={
                'note': note,
                'message': msg,
                'sub': data.get('sub', '')
            }
        )
        
        return event
    
    def _parse_files(self, data: Dict, source_host: str, scenario_id: str, file_path: Path) -> ParsedEvent:
        """Parse Zeek files log"""
        
        timestamp = self._parse_timestamp_zeek(data.get('ts'))
        
        event = ParsedEvent(
            source_type='zeek',
            source_file=str(file_path),
            source_host=source_host,
            scenario_id=scenario_id,
            timestamp_utc=timestamp,
            action_category='file_transfer',
            action_name='file_detected',
            protocol='file',
            network_uid=data.get('uid', ''),
            src_ip=data.get('id.orig_h', ''),
            dest_ip=data.get('id.resp_h', ''),
            result='success' if data.get('seen') else 'failure',
            raw_data=json.dumps(data),
            parsed_data={
                'filename': data.get('filename', ''),
                'mime_type': data.get('mime', ''),
                'size': data.get('size', 0)
            }
        )
        
        return event
    
    def _parse_generic(self, data: Dict, source_host: str, scenario_id: str, file_path: Path) -> ParsedEvent:
        """Generic Zeek log parser"""
        
        timestamp = self._parse_timestamp_zeek(data.get('ts'))
        
        return ParsedEvent(
            source_type='zeek',
            source_file=str(file_path),
            source_host=source_host,
            scenario_id=scenario_id,
            timestamp_utc=timestamp,
            action_category='network',
            action_name='zeek_event',
            raw_data=json.dumps(data),
            parsed_data=data
        )
    
    def _parse_timestamp_zeek(self, ts: Any) -> datetime:
        """Parse Zeek timestamp (Unix epoch with optional decimals)"""
        if ts is None:
            return datetime.now()
        
        try:
            ts_float = float(ts)
            return datetime.fromtimestamp(ts_float)
        except:
            return datetime.now()
    
    def _map_conn_state(self, state: str) -> str:
        """Map Zeek connection states to simple result"""
        state_map = {
            'REJ': 'rejected',
            'RSTO': 'reset_orig',
            'RSTR': 'reset_resp',
            'S0': 'connect_orig',
            'S1': 'connect_resp',
            'S2': 'established',
            'S3': 'established',
            'SF': 'finished',
            'SH': 'shutdown',
            'SHR': 'shutdown_resp',
            'S2R': 'shutdown_resp',
            'OTH': 'other',
        }
        return state_map.get(state, state.lower())
