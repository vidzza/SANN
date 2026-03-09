"""
OBSIDIAN - Behavior Tracking JSONL Parser
Parser for bt.jsonl files (Behavior Tracking)
"""

import json
import logging
from pathlib import Path
from typing import Iterator
from datetime import datetime

from parsers.base import BaseParser, ParsedEvent

logger = logging.getLogger(__name__)

class BTJsonLParser(BaseParser):
    """
    Parser for Behavior Tracking JSONL files
    
    Example:
    {"index":"rootkit-dockeragent_dockerinterfacing","loglevel":"2","message":"Proceeding to check open ports...","source":"DockerAgent_DockerInterfacing","timestamp":"2025-07-20T14:00:29Z"}
    """
    
    def can_parse(self, file_path: Path) -> bool:
        """Check if this is a bt.jsonl file"""
        return file_path.name == 'bt.jsonl'
    
    def parse(self, file_path: Path) -> Iterator[ParsedEvent]:
        """Parse bt.jsonl file"""
        source_host = self.extract_host_from_path(file_path)
        scenario_id = self.extract_scenario_from_path(file_path)
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        data = json.loads(line)
                        event = self._parse_json_event(data, source_host, scenario_id, file_path)
                        if event:
                            self.events_parsed += 1
                            yield event
                    except json.JSONDecodeError:
                        self.errors += 1
                        logger.debug(f"Invalid JSON at line {line_num}")
                    except Exception as e:
                        self.errors += 1
                        logger.debug(f"Error parsing line {line_num}: {e}")
                        
        except Exception as e:
            self.errors += 1
            logger.error(f"Error opening bt.jsonl file {file_path}: {e}")
    
    def _parse_json_event(self, data: dict, source_host: str, scenario_id: str, file_path: Path) -> ParsedEvent:
        """Parse a single JSON event from bt.jsonl"""
        
        # Extract timestamp
        timestamp = None
        ts_value = data.get('timestamp', '')
        if ts_value:
            timestamp = self._parse_timestamp(ts_value)
        
        # Extract log level
        loglevel = data.get('loglevel', '0')
        
        # Determine alert severity from log level
        alert_severity = 0
        try:
            lvl = int(loglevel)
            if lvl == 0:
                alert_severity = 5
            elif lvl == 1:
                alert_severity = 7
            elif lvl == 2:
                alert_severity = 3
            elif lvl >= 3:
                alert_severity = 10
        except:
            pass
        
        # Extract source/component
        source = data.get('source', '')
        
        # Determine action from source and message
        action_name = 'behavior_event'
        action_category = 'behavior'
        tool = ''
        alert_type = ''
        
        if 'docker' in source.lower():
            tool = 'docker'
            action_name = 'docker_activity'
            action_category = 'execution'
        elif 'honey' in source.lower():
            tool = 'honeypot'
            action_name = 'honeypot_activity'
            action_category = 'detection'
        elif 'rootkit' in source.lower():
            action_name = 'rootkit_activity'
            action_category = 'persistence'
            alert_type = 'rootkit'
        
        # Determine result based on message content
        message = data.get('message', '')
        result = 'success'
        if 'error' in message.lower() or 'fail' in message.lower():
            result = 'failure'
        
        event = ParsedEvent(
            source_type='bt_jsonl',
            source_file=str(file_path),
            source_host=source_host,
            scenario_id=scenario_id,
            timestamp_utc=timestamp,
            action_category=action_category,
            action_name=action_name,
            tool=tool,
            result=result,
            alert_type=alert_type,
            alert_severity=alert_severity,
            detection_source='behavior_tracking',
            raw_data=json.dumps(data),
            parsed_data=data
        )
        
        return event
