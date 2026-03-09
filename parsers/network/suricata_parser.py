"""
OBSIDIAN - Suricata Parser
Parser for Suricata IDS logs (eve.json, fast.log)
"""

import json
import logging
from pathlib import Path
from typing import Iterator, Dict, Any
from datetime import datetime

from parsers.base import BaseParser, ParsedEvent

logger = logging.getLogger(__name__)

class SuricataParser(BaseParser):
    """
    Parser for Suricata IDS logs
    
    Handles:
    - eve.json: JSON events
    - fast.log: Fast alerts
    """
    
    def can_parse(self, file_path: Path) -> bool:
        """Check if this is a Suricata log file"""
        parent = file_path.parent.name
        filename = file_path.name
        return parent == 'suricata' and filename in ['eve.json', 'fast.log']
    
    def parse(self, file_path: Path) -> Iterator[ParsedEvent]:
        """Parse Suricata log file"""
        source_host = self.extract_host_from_path(file_path)
        scenario_id = self.extract_scenario_from_path(file_path)
        
        if file_path.name == 'eve.json':
            yield from self._parse_eve_json(file_path, source_host, scenario_id)
        elif file_path.name == 'fast.log':
            yield from self._parse_fast_log(file_path, source_host, scenario_id)
    
    def _parse_eve_json(self, file_path: Path, source_host: str, scenario_id: str) -> Iterator[ParsedEvent]:
        """Parse Suricata eve.json file"""
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        data = json.loads(line)
                        event = self._parse_eve_event(data, source_host, scenario_id, file_path)
                        if event:
                            self.events_parsed += 1
                            yield event
                    except json.JSONDecodeError:
                        self.errors += 1
                        
        except Exception as e:
            self.errors += 1
            logger.error(f"Error opening eve.json {file_path}: {e}")
    
    def _parse_eve_event(self, data: Dict, source_host: str, scenario_id: str, file_path: Path) -> ParsedEvent:
        """Parse a single eve.json event"""
        
        event_type = data.get('event_type', 'unknown')
        timestamp = self._parse_timestamp(data.get('timestamp'))
        
        if event_type == 'stats':
            # Stats event - can be used for context
            return ParsedEvent(
                source_type='suricata',
                source_file=str(file_path),
                source_host=source_host,
                scenario_id=scenario_id,
                timestamp_utc=timestamp,
                action_category='network',
                action_name='ids_stats',
                result='success',
                raw_data=json.dumps(data),
                parsed_data=data
            )
        
        elif event_type == 'flow':
            # Flow event
            src_ip = data.get('src_ip', '')
            dest_ip = data.get('dest_ip', '')
            src_port = data.get('src_port', 0)
            dest_port = data.get('dest_port', 0)
            proto = data.get('proto', '')
            app_proto = data.get('app_proto', '')
            
            return ParsedEvent(
                source_type='suricata',
                source_file=str(file_path),
                source_host=source_host,
                scenario_id=scenario_id,
                timestamp_utc=timestamp,
                action_category='network',
                action_name='flow',
                protocol=proto,
                network_uid=str(data.get('flow_id', '')),
                src_ip=src_ip,
                src_port=src_port,
                dest_ip=dest_ip,
                dest_port=dest_port,
                result='success',
                raw_data=json.dumps(data),
                parsed_data=data
            )
        
        elif event_type == 'alert':
            # Alert event - security incident
            alert = data.get('alert', {})
            signature = alert.get('signature', '')
            category = alert.get('category', '')
            severity = alert.get('severity', 0)
            
            # Determine MITRE tactic from signature (simplified)
            mitre_tactic = self._map_to_mitre(signature)
            
            return ParsedEvent(
                source_type='suricata',
                source_file=str(file_path),
                source_host=source_host,
                scenario_id=scenario_id,
                timestamp_utc=timestamp,
                action_category='detection',
                action_name='ids_alert',
                alert_type=category,
                alert_severity=severity,
                detection_source='suricata',
                mitre_tactic=mitre_tactic,
                src_ip=data.get('src_ip', ''),
                dest_ip=data.get('dest_ip', ''),
                src_port=data.get('src_port', 0),
                dest_port=data.get('dest_port', 0),
                protocol=data.get('proto', ''),
                result='alert',
                raw_data=json.dumps(data),
                parsed_data={
                    'signature': signature,
                    'category': category,
                    'severity': severity,
                    'message': alert.get('message', '')
                }
            )
        
        elif event_type == 'http':
            # HTTP traffic
            return ParsedEvent(
                source_type='suricata',
                source_file=str(file_path),
                source_host=source_host,
                scenario_id=scenario_id,
                timestamp_utc=timestamp,
                action_category='network',
                action_name='http_traffic',
                protocol='http',
                src_ip=data.get('src_ip', ''),
                dest_ip=data.get('dest_ip', ''),
                src_port=data.get('src_port', 0),
                dest_port=data.get('dest_port', 0),
                http_method=data.get('http', {}).get('method', ''),
                url=data.get('http', {}).get('url', ''),
                user_agent=data.get('http', {}).get('user_agent', ''),
                http_status=int(data.get('http', {}).get('status', 0)) if data.get('http', {}).get('status') else 0,
                raw_data=json.dumps(data),
                parsed_data=data
            )
        
        elif event_type == 'dns':
            # DNS query
            dns_data = data.get('dns', {})
            return ParsedEvent(
                source_type='suricata',
                source_file=str(file_path),
                source_host=source_host,
                scenario_id=scenario_id,
                timestamp_utc=timestamp,
                action_category='network',
                action_name='dns_query',
                protocol='dns',
                src_ip=data.get('src_ip', ''),
                dest_ip=data.get('dest_ip', ''),
                dest_port=53,
                url=dns_data.get('query', ''),
                raw_data=json.dumps(data),
                parsed_data=data
            )
        
        else:
            # Generic event
            return ParsedEvent(
                source_type='suricata',
                source_file=str(file_path),
                source_host=source_host,
                scenario_id=scenario_id,
                timestamp_utc=timestamp,
                action_category='network',
                action_name=f'suricata_{event_type}',
                raw_data=json.dumps(data),
                parsed_data=data
            )
    
    def _parse_fast_log(self, file_path: Path, source_host: str, scenario_id: str) -> Iterator[ParsedEvent]:
        """Parse Suricata fast.log file"""
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    try:
                        event = self._parse_fast_line(line, source_host, scenario_id, file_path)
                        if event:
                            self.events_parsed += 1
                            yield event
                    except Exception as e:
                        self.errors += 1
                        
        except Exception as e:
            self.errors += 1
            logger.error(f"Error opening fast.log {file_path}: {e}")
    
    def _parse_fast_line(self, line: str, source_host: str, scenario_id: str, file_path: Path) -> ParsedEvent:
        """Parse a single fast.log line"""
        
        # Format: **[Classification] [Priority] Signature -> [Message]
        import re
        pattern = re.compile(
            r'\*\*\[(?P<classification>[^\]]+)\]\s*'
            r'\[(?P<priority>\d+)\]\s*'
            r'(?P<signature>[^->]+)\s*->\s*'
            r'\[(?P<message>[^\]]+)\]'
        )
        
        match = pattern.match(line)
        
        if match:
            groups = match.groupdict()
            
            severity = int(groups.get('priority', 5))
            mitre_tactic = self._map_to_mitre(groups.get('signature', ''))
            
            return ParsedEvent(
                source_type='suricata',
                source_file=str(file_path),
                source_host=source_host,
                scenario_id=scenario_id,
                timestamp_utc=datetime.now(),
                action_category='detection',
                action_name='ids_alert',
                alert_type=groups.get('classification', ''),
                alert_severity=severity,
                detection_source='suricata',
                mitre_tactic=mitre_tactic,
                result='alert',
                raw_data=line,
                parsed_data={
                    'signature': groups.get('signature', ''),
                    'message': groups.get('message', '')
                }
            )
        
        return ParsedEvent(
            source_type='suricata',
            source_file=str(file_path),
            source_host=source_host,
            scenario_id=scenario_id,
            action_name='suricata_event',
            raw_data=line
        )
    
    def _parse_timestamp(self, ts: Any) -> datetime:
        """Parse ISO timestamp"""
        if ts is None:
            return datetime.now()
        
        try:
            return datetime.fromisoformat(ts.replace('Z', '+00:00'))
        except:
            return datetime.now()
    
    def _map_to_mitre(self, signature: str) -> str:
        """Map signature to MITRE ATT&CK tactic (simplified)"""
        signature_lower = signature.lower()
        
        # Simplified mapping - in production, use proper MITRE mapping
        if any(x in signature_lower for x in ['port scan', 'nmap', 'scan']):
            return 'TA0043'  # Reconnaissance
        if any(x in signature_lower for x in ['brute force', 'password', 'login failed']):
            return 'TA0006'  # Credential Access
        if any(x in signature_lower for x in ['web attack', 'sqli', 'xss', 'injection']):
            return 'TA0001'  # Initial Access
        if any(x in signature_lower for x in ['shellcode', 'exploit', 'cve']):
            return 'TA0002'  # Execution
        if any(x in signature_lower for x in ['malware', 'trojan', 'backdoor']):
            return 'TA0001'  # Initial Access / Persistence
        if any(x in signature_lower for x in ['ransomware', 'file encryption']):
            return 'TA0040'  # Impact
        
        return ''
