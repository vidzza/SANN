"""
OBSIDIAN - UAT Parser
User Activity Timeline parser for UAT-*.tsv files
"""

import logging
import re
from pathlib import Path
from typing import Iterator, Optional
from datetime import datetime

from parsers.base import BaseParser, ParsedEvent

logger = logging.getLogger(__name__)

class UATParser(BaseParser):
    """
    Parser for UAT (User Activity Timeline) files
    
    UAT files contain:
    - Timestamps (Unix milliseconds)
    - Window titles
    - Application names
    - Working directories
    - Commands executed
    - UI interactions
    """
    
    def can_parse(self, file_path: Path) -> bool:
        """Check if this is a UAT file"""
        return file_path.name.startswith('UAT-') and file_path.suffix == '.tsv'
    
    def parse(self, file_path: Path) -> Iterator[ParsedEvent]:
        """
        Parse UAT file and yield events
        
        Example line:
        1753044109585  16777217  Xfce4-panel  xfce4-panel  P-WL-WWO  ||0|Window|<none>|False|...
        """
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
            logger.error(f"Error opening UAT file {file_path}: {e}")
    
    def _parse_line(self, line: str, source_host: str, scenario_id: str, file_path: Path) -> Optional[ParsedEvent]:
        """Parse a single line from UAT file"""
        parts = line.split('\t')
        
        if len(parts) < 4:
            return None
        
        # Parse timestamp (first column - Unix milliseconds)
        timestamp_ms = parts[0].strip()
        try:
            timestamp = datetime.fromtimestamp(int(timestamp_ms) / 1000)
        except:
            timestamp = None
        
        # PID / Window ID
        pid = parts[1].strip() if len(parts) > 1 else ""
        
        # Application/window title
        app_name = parts[2].strip() if len(parts) > 2 else ""
        window_title = parts[3].strip() if len(parts) > 3 else ""
        
        # Event type (4th field)
        event_type = parts[4].strip() if len(parts) > 4 else ""
        
        # Rest is the data
        extra_data = '\t'.join(parts[5:]) if len(parts) > 5 else ""
        
        event = ParsedEvent(
            source_type='uat',
            source_file=str(file_path),
            source_host=source_host,
            scenario_id=scenario_id,
            timestamp_utc=timestamp,
            raw_data=line,
            parsed_data={
                'pid': pid,
                'app_name': app_name,
                'window_title': window_title,
                'event_type': event_type,
                'extra_data': extra_data,
            }
        )
        
        # Determine action based on application and event type
        event.action_category = 'execution'
        
        # Check for terminal applications
        terminal_patterns = ['qterminal', 'xterm', 'gnome-terminal', 'konsole', 'terminal']
        if any(t in app_name.lower() for t in terminal_patterns):
            event.action_name = 'terminal_session'
            event.tool = self._detect_tool_from_title(window_title)
            
            # Extract command from window title (e.g., "root@dmz-jumpbox-1: /tmp")
            if '@' in window_title:
                match = re.search(r'@([^:]+):\s*(.*)', window_title)
                if match:
                    event.user = window_title.split('@')[0]
                    event.source_host = match.group(1)
                    event.working_dir = match.group(2)
        
        # Check for text editors
        editor_patterns = ['mousepad', 'vim', 'nano', 'gedit', 'code']
        if any(e in app_name.lower() for e in editor_patterns):
            event.action_name = 'file_edit'
            event.tool = app_name.lower()
            if window_title:
                event.parsed_data['file_being_edited'] = window_title
        
        # Check for browsers
        if 'firefox' in app_name.lower() or 'chrome' in app_name.lower() or 'chromium' in app_name.lower():
            event.action_name = 'web_browse'
            event.tool = app_name.lower()
            if window_title:
                event.parsed_data['url_or_tab'] = window_title
        
        # Check for file manager
        if 'thunar' in app_name.lower() or 'nautilus' in app_name.lower() or 'dolphin' in app_name.lower():
            event.action_name = 'file_browse'
            event.tool = app_name.lower()
            if window_title:
                event.working_dir = window_title
        
        # Default: window focus event
        if not event.action_name:
            if 'Window' in event_type:
                event.action_name = 'window_focus'
            elif 'Button' in event_type:
                event.action_name = 'ui_click'
            else:
                event.action_name = 'ui_activity'
        
        return event
    
    def _detect_tool_from_title(self, window_title: str) -> str:
        """Detect security tool from terminal title"""
        tools = [
            'nmap', 'nikto', 'sqlmap', 'hydra', 'msfconsole', 'metasploit',
            'gobuster', 'dirb', 'ffuf', 'feroxbuster', 'wpscan', 'burp', 'zap',
            'nc', 'netcat', 'socat', 'curl', 'wget', 'ssh', 'ftp', 'telnet',
            'john', 'hashcat', 'aircrack', 'responder', 'impacket', 'mimikatz',
            'linpeas', 'linenum', 'pspy', 'gtfobins', 'pspy64'
        ]
        
        title_lower = window_title.lower()
        for tool in tools:
            if tool in title_lower:
                return tool
        
        return 'terminal'
