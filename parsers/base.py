"""
OBSIDIAN - Base Parser Module
Base class for all parsers
"""

import json
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterator, Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
import uuid

logger = logging.getLogger(__name__)

@dataclass
class ParsedEvent:
    """Standardized event from any parser"""
    # Meta
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    scenario_id: str = ""
    timestamp_utc: Optional[datetime] = None
    ingest_timestamp: datetime = field(default_factory=datetime.utcnow)
    
    # Source
    source_type: str = ""      # uat, auth, bt_jsonl, zeek, etc.
    source_file: str = ""
    source_host: str = ""
    
    # Network
    src_ip: str = ""
    src_port: int = 0
    dest_ip: str = ""
    dest_port: int = 0
    protocol: str = ""
    network_uid: str = ""
    
    # Host
    host_role: str = ""
    network_zone: str = ""
    
    # User
    user: str = ""
    user_type: str = ""
    session_id: str = ""
    tty: str = ""
    
    # Action
    action_category: str = ""
    action_name: str = ""
    tool: str = ""
    result: str = ""
    
    # Technical
    command: str = ""
    arguments: str = ""
    working_dir: str = ""
    process_id: int = 0
    
    # Attack context
    mitre_tactic: str = ""
    mitre_technique: str = ""
    attack_phase: str = ""
    
    # Security events
    alert_type: str = ""
    alert_severity: int = 0
    detection_source: str = ""
    
    # Web context
    http_method: str = ""
    url: str = ""
    user_agent: str = ""
    http_status: int = 0
    
    # SSH context
    ssh_client: str = ""
    ssh_server: str = ""
    ssh_version: str = ""
    auth_success: Optional[bool] = None
    auth_attempts: int = 0
    
    # Raw data
    raw_data: str = ""
    parsed_data: Dict[str, Any] = field(default_factory=dict)

class BaseParser(ABC):
    """Base class for all file parsers"""
    
    def __init__(self):
        self.events_parsed = 0
        self.errors = 0
        
    @abstractmethod
    def parse(self, file_path: Path) -> Iterator[ParsedEvent]:
        """
        Parse a file and yield events
        
        Args:
            file_path: Path to file to parse
            
        Yields:
            ParsedEvent objects
        """
        pass
    
    @abstractmethod
    def can_parse(self, file_path: Path) -> bool:
        """
        Check if this parser can handle the file
        
        Args:
            file_path: Path to file
            
        Returns:
            True if parser can handle this file
        """
        pass
    
    def extract_host_from_path(self, file_path: Path) -> str:
        """Extract hostname from file path"""
        path_str = str(file_path)
        parts = path_str.split('/')
        
        # Look for host patterns
        host_patterns = ['atkr-', 'dmz-', 'int-', 'sec-', 'mgmt-', 'workstation-']
        
        for part in parts:
            for pattern in host_patterns:
                if pattern in part:
                    return part
                    
        # Try to get parent directory name
        if len(parts) >= 2:
            return parts[-2]
            
        return ""
    
    def extract_scenario_from_path(self, file_path: Path) -> str:
        """Extract scenario ID from file path"""
        path_str = str(file_path)
        parts = path_str.split('/')
        
        # Look for scenario patterns
        scenario_patterns = ['training', 'ckc1', 'ckc2', 'ckc3']
        
        for part in parts:
            for pattern in scenario_patterns:
                if pattern in part and part != pattern:
                    return part
                    
        # Return first part (usually P003, user0003, etc)
        if parts:
            return parts[0]
            
        return ""
    
    def _safe_get(self, data: Dict, key: str, default: Any = "") -> Any:
        """Safely get value from dict"""
        return data.get(key, default)
    
    def _parse_timestamp(self, timestamp: Any) -> Optional[datetime]:
        """Parse timestamp from various formats"""
        if isinstance(timestamp, datetime):
            return timestamp
        if isinstance(timestamp, (int, float)):
            # Unix timestamp
            try:
                return datetime.fromtimestamp(timestamp)
            except:
                # Could be milliseconds
                try:
                    return datetime.fromtimestamp(timestamp / 1000)
                except:
                    return None
        if isinstance(timestamp, str):
            # ISO format
            try:
                return datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except:
                # Try common formats
                formats = [
                    '%Y-%m-%d %H:%M:%S',
                    '%Y-%m-%dT%H:%M:%S',
                    '%Y/%m/%d %H:%M:%S',
                    '%b %d %H:%M:%S',
                ]
                for fmt in formats:
                    try:
                        return datetime.strptime(timestamp, fmt)
                    except:
                        continue
        return None
    
    def get_stats(self) -> Dict[str, int]:
        """Get parser statistics"""
        return {
            'events_parsed': self.events_parsed,
            'errors': self.errors
        }
