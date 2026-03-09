"""
OBSIDIAN - Sensor Log Parser
Parser for sensor.log files
"""

import json
import logging
from pathlib import Path
from typing import Iterator
from datetime import datetime

from parsers.base import BaseParser, ParsedEvent

logger = logging.getLogger(__name__)

class SensorParser(BaseParser):
    """
    Parser for sensor.log files
    
    Example:
    {'time': 1753042450.5991843, 'type': 'PACKET', 'data': {'src_ip': '122.10.11.101', 'src_port': 40744, 'dst_ip': '10.0.200.50', 'dst_port': 80, 'payload': ''}}
    """
    
    def can_parse(self, file_path: Path) -> bool:
        """Check if this is a sensor.log file"""
        return file_path.name == 'sensor.log'
    
    def parse(self, file_path: Path) -> Iterator[ParsedEvent]:
        """Parse sensor.log file"""
        source_host = self.extract_host_from_path(file_path)
        scenario_id = self.extract_scenario_from_path(file_path)
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        # Sensor logs are Python dict literals
                        data = eval(line)
                        event = self._parse_sensor_data(data, source_host, scenario_id, file_path)
                        if event:
                            self.events_parsed += 1
                            yield event
                    except Exception as e:
                        self.errors += 1
                        logger.debug(f"Error parsing sensor line {line_num}: {e}")
                        
        except Exception as e:
            self.errors += 1
            logger.error(f"Error opening sensor.log {file_path}: {e}")
    
    def _parse_sensor_data(self, data: dict, source_host: str, scenario_id: str, file_path: Path) -> ParsedEvent:
        """Parse sensor data dict"""
        
        # Get timestamp
        ts = data.get('time')
        if ts:
            try:
                timestamp = datetime.fromtimestamp(ts)
            except:
                timestamp = datetime.now()
        else:
            timestamp = datetime.now()
        
        sensor_type = data.get('type', 'unknown')
        packet_data = data.get('data', {})
        
        src_ip = packet_data.get('src_ip', '')
        src_port = packet_data.get('src_port', 0)
        dest_ip = packet_data.get('dest_ip', '')
        dest_port = packet_data.get('dest_port', 0)
        payload = packet_data.get('payload', '')
        
        # Determine action
        action_name = 'packet_captured'
        action_category = 'network'
        
        if payload:
            if 'GET' in payload or 'POST' in payload or 'HTTP' in payload:
                action_name = 'http_request'
            elif 'SSH' in payload:
                action_name = 'ssh_traffic'
            else:
                action_name = 'packet_with_payload'
        
        # Extract HTTP details if present
        http_method = ''
        url = ''
        if 'GET' in payload:
            http_method = 'GET'
            parts = payload.split('\n')[0].split(' ')
            if len(parts) >= 2:
                url = parts[1]
        elif 'POST' in payload:
            http_method = 'POST'
            parts = payload.split('\n')[0].split(' ')
            if len(parts) >= 2:
                url = parts[1]
        
        event = ParsedEvent(
            source_type='sensor',
            source_file=str(file_path),
            source_host=source_host,
            scenario_id=scenario_id,
            timestamp_utc=timestamp,
            action_category=action_category,
            action_name=action_name,
            protocol='tcp',  # Assume TCP for packet captures
            src_ip=src_ip,
            src_port=src_port,
            dest_ip=dest_ip,
            dest_port=dest_port,
            result='success',
            raw_data=str(data),
            parsed_data={
                'sensor_type': sensor_type,
                'payload': payload[:500] if payload else '',  # Truncate long payloads
                'payload_length': len(payload)
            }
        )
        
        if http_method:
            event.http_method = http_method
        if url:
            event.url = url
            
        return event
