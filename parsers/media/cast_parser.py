"""
OBSIDIAN - Cast Parser
Parses .cast (terminal recording) files from asciinema
"""

import json
import logging
from pathlib import Path
from typing import Iterator, Dict, Any
from datetime import datetime, timedelta

from parsers.base import BaseParser, ParsedEvent

logger = logging.getLogger(__name__)


class CastParser(BaseParser):
    """Parser for terminal recording files (.cast)"""
    
    def __init__(self):
        super().__init__()
        self.supported_extensions = ['.cast']
    
    def can_parse(self, file_path: Path) -> bool:
        """Check if file is a cast file"""
        return file_path.suffix.lower() == '.cast'
    
    def parse(self, file_path: Path) -> Iterator[ParsedEvent]:
        """
        Parse cast file to extract terminal recording metadata
        
        .cast files are JSONL format from asciinema
        Format: [timestamp, type, data]
        
        Yields:
            ParsedEvent with terminal recording metadata
        """
        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            return
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                first_line = f.readline()
            
            # Try to parse header
            header = json.loads(first_line)
            
            # Extract header metadata
            version = header.get('version', 'unknown')
            width = header.get('width', 0)
            height = header.get('height', 0)
            timestamp_start = header.get('timestamp', 0)
            
            # Get file stats
            stat = file_path.stat()
            
            # Count total lines for duration estimation
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                total_lines = sum(1 for _ in f)
            
            # Estimate duration based on last timestamp
            duration = 0
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    last_line = None
                    for last_line in f:
                        pass
                    if last_line:
                        last_event = json.loads(last_line)
                        if isinstance(last_event, list) and len(last_event) > 0:
                            duration = last_event[0]
            except:
                duration = total_lines * 0.1  # Rough estimate
            
            # Create main event for the recording
            event = ParsedEvent()
            event.source_type = 'terminal_recording'
            event.source_file = str(file_path)
            event.source_host = self.extract_host_from_path(file_path)
            event.scenario_id = self.extract_scenario_from_path(file_path)
            
            event.action_name = 'terminal_recording'
            event.action_category = 'media'
            event.tool = 'asciinema'
            
            event.timestamp_utc = datetime.fromtimestamp(timestamp_start) if timestamp_start else datetime.now()
            
            event.parsed_data = {
                'format': 'asciinema_cast',
                'version': version,
                'width': width,
                'height': height,
                'duration_sec': round(duration, 2),
                'total_lines': total_lines,
                'filename': file_path.name,
                'size_bytes': stat.st_size
            }
            
            event.raw_data = f"filename={file_path.name}|version={version}|duration={duration}|size={stat.st_size}"
            
            self.events_parsed += 1
            yield event
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse cast file {file_path}: {e}")
        except Exception as e:
            logger.error(f"Error parsing cast file {file_path}: {e}")
