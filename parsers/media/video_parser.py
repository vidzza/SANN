"""
OBSIDIAN - Video Parser
Parses .ogv (Ogg Video) and .mp4 files to extract metadata
"""

import logging
import os
from pathlib import Path
from typing import Iterator, Dict, Any
from datetime import datetime

from parsers.base import BaseParser, ParsedEvent

logger = logging.getLogger(__name__)


class VideoParser(BaseParser):
    """Parser for video recording files (.ogv, .mp4)"""
    
    def __init__(self):
        super().__init__()
        self.supported_extensions = ['.ogv', '.mp4', '.webm']
    
    def can_parse(self, file_path: Path) -> bool:
        """Check if file is a video file"""
        return file_path.suffix.lower() in self.supported_extensions
    
    def parse(self, file_path: Path) -> Iterator[ParsedEvent]:
        """
        Parse video file to extract metadata
        
        Yields:
            ParsedEvent with video metadata
        """
        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            return
        
        # Get file stats
        stat = file_path.stat()
        
        # Extract metadata
        event = ParsedEvent()
        event.source_type = 'video'
        event.source_file = str(file_path)
        event.source_host = self.extract_host_from_path(file_path)
        event.scenario_id = self.extract_scenario_from_path(file_path)
        
        # Video metadata
        event.action_name = 'video_recording'
        event.action_category = 'media'
        event.tool = 'screen_capture'
        
        # File info
        event.raw_data = f"filename={file_path.name}|size_bytes={stat.st_size}|created={datetime.fromtimestamp(stat.st_ctime)}|modified={datetime.fromtimestamp(stat.st_mtime)}"
        
        # Duration estimation based on file size (rough estimate for ogv/webm)
        # Average bitrate ~500kbps for screen recordings
        if file_path.suffix.lower() == '.ogv':
            estimated_duration_sec = stat.st_size / (500 * 1024 / 8)
            event.parsed_data = {
                'format': 'ogv',
                'size_bytes': stat.st_size,
                'estimated_duration_sec': round(estimated_duration_sec, 2),
                'filename': file_path.name
            }
        elif file_path.suffix.lower() == '.mp4':
            event.parsed_data = {
                'format': 'mp4',
                'size_bytes': stat.st_size,
                'filename': file_path.name
            }
        else:
            event.parsed_data = {
                'format': file_path.suffix.lower(),
                'size_bytes': stat.st_size,
                'filename': file_path.name
            }
        
        self.events_parsed += 1
        yield event
