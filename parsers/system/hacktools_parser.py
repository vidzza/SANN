"""
OBSIDIAN - HackTools Parser
Parser for hacktools.log files
"""

import re
import logging
from pathlib import Path
from typing import Iterator
from datetime import datetime

from parsers.base import BaseParser, ParsedEvent

logger = logging.getLogger(__name__)

class HackToolsParser(BaseParser):
    """
    Parser for hacktools.log files
    
    Example:
    114.0.194.2 - - [20/Jul/2025 16:19:28] "GET /exploits/ HTTP/1.1" 200 -
    """
    
    # Apache common log format
    LOG_PATTERN = re.compile(
        r'^(?P<ip>\S+)\s+-\s+-\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\S+)\s+(?P<url>\S+)\s+(?P<protocol>[^"]+)"\s+'
        r'(?P<status>\d+)\s+'
        r'(?P<size>\S+)'
    )
    
    def can_parse(self, file_path: Path) -> bool:
        """Check if this is a hacktools.log file"""
        return file_path.name == 'hacktools.log'
    
    def parse(self, file_path: Path) -> Iterator[ParsedEvent]:
        """Parse hacktools.log file"""
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
                        logger.debug(f"Error parsing hacktools line {line_num}: {e}")
                        
        except Exception as e:
            self.errors += 1
            logger.error(f"Error opening hacktools.log {file_path}: {e}")
    
    def _parse_line(self, line: str, source_host: str, scenario_id: str, file_path: Path) -> ParsedEvent:
        """Parse a single hacktools log line"""
        
        match = self.LOG_PATTERN.match(line)
        
        if match:
            groups = match.groupdict()
            
            ip = groups.get('ip', '')
            timestamp_str = groups.get('timestamp', '')
            method = groups.get('method', '')
            url = groups.get('url', '')
            status = int(groups.get('status', 0))
            
            timestamp = self._parse_apache_timestamp(timestamp_str)
            
            # Determine tool from URL
            tool = self._detect_tool_from_url(url)
            
            # Determine result
            result = 'success' if status == 200 else 'failure'
            if status >= 400:
                result = 'error'
            
            # Detect attack tools
            is_attack_tool = any(t in url.lower() for t in [
                'cupp', 'exploit', 'payload', 'shell', 'backdoor',
                'password', 'wordlist', 'hashcat', 'john', 'nmap',
                'metasploit', 'cve', 'vuln', 'scanner'
            ])
            
            action_category = 'web_access'
            action_name = 'web_request'
            
            if is_attack_tool:
                action_category = 'tool_download'
                action_name = 'tool_accessed'
            
            event = ParsedEvent(
                source_type='hacktools',
                source_file=str(file_path),
                source_host=source_host,
                scenario_id=scenario_id,
                timestamp_utc=timestamp,
                action_category=action_category,
                action_name=action_name,
                tool=tool,
                src_ip=ip,
                dest_port=80,
                http_method=method,
                url=url,
                http_status=status,
                result=result,
                raw_data=line,
                parsed_data={
                    'ip': ip,
                    'method': method,
                    'url': url,
                    'protocol': groups.get('protocol', ''),
                    'status': status,
                    'size': groups.get('size', '')
                }
            )
            
            return event
        
        # Fallback
        return ParsedEvent(
            source_type='hacktools',
            source_file=str(file_path),
            source_host=source_host,
            scenario_id=scenario_id,
            action_name='hacktools_event',
            raw_data=line
        )
    
    def _detect_tool_from_url(self, url: str) -> str:
        """Detect security tool from URL"""
        url_lower = url.lower()
        
        tools = [
            'cupp', 'exploit', 'payload', 'shell', 'backdoor',
            'password', 'wordlist', 'hashcat', 'john', 'nmap',
            'metasploit', 'cve', 'vuln', 'scanner', 'impacket',
            'responder', 'mimikatz', 'linpeas', 'pspy',
            'gobuster', 'dirb', 'ffuf', 'feroxbuster'
        ]
        
        for tool in tools:
            if tool in url_lower:
                return tool
        
        return 'web'
    
    def _parse_apache_timestamp(self, ts: str) -> datetime:
        """Parse Apache timestamp format: 20/Jul/2025 16:19:28"""
        try:
            return datetime.strptime(ts, "%d/%b/%Y %H:%M:%S")
        except:
            return datetime.now()
