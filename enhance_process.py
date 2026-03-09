#!/usr/bin/env python3
"""
GOD EYE - Enhanced Data Processor
Processes cybersecurity datasets with improved command extraction
"""

import sys
import re
import json
import logging
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Add code directory to path
sys.path.insert(0, str(Path(__file__).parent))

from storage.database import ObsidianDB
from parsers.activity.uat_parser import UATParser
from parsers.behavior.bt_jsonl_parser import BTJsonLParser
from parsers.behavior.sensor_parser import SensorParser
from parsers.system.auth_parser import AuthParser
from parsers.system.syslog_parser import SyslogParser
from parsers.system.hacktools_parser import HackToolsParser
from parsers.network.zeek_parser import ZeekParser
from parsers.network.suricata_parser import SuricataParser
from parsers.media.video_parser import VideoParser
from parsers.media.cast_parser import CastParser
from parsers.media.pcap_parser import PcapParser
from ingestor import FileDiscovery


# Command extraction patterns
COMMAND_PATTERNS = {
    'auth': re.compile(r'COMMAND=(.+?)(?:\s+\w+=|$)'),
    'ssh': re.compile(r'ssh(?:\s+-|\s+[^\s]+\s+-)?([^\s]+)'),
    'docker': re.compile(r'docker(?:\s+[a-z]+)*\s+(.+?)(?:\s+--|$)'),
    'sudo': re.compile(r'sudo\s+(.+?)(?:\s+[|&;]|$)'),
}


def extract_command_from_raw(raw_data: str, source_type: str) -> str:
    """Extract command from raw log data"""
    if not raw_data:
        return ''
    
    # Try auth log pattern (COMMAND=...)
    if 'COMMAND=' in raw_data:
        match = COMMAND_PATTERNS['auth'].search(raw_data)
        if match:
            return match.group(1).strip()[:200]
    
    # Try general command patterns
    for pattern_name, pattern in COMMAND_PATTERNS.items():
        if pattern_name != 'auth':
            match = pattern.search(raw_data)
            if match:
                return match.group(1).strip()[:200]
    
    return ''


def extract_tool_from_command(command: str) -> str:
    """Detect tool from command"""
    if not command:
        return ''
    
    cmd_lower = command.lower()
    
    tool_patterns = {
        'ssh': [r'ssh', r'sshpass', r'scp', r'sftp'],
        'docker': [r'docker', r'docker-compose', r'podman'],
        'nmap': [r'nmap'],
        'metasploit': [r'msfconsole', r'msfvenom', r'msf'],
        'sqlmap': [r'sqlmap'],
        'hydra': [r'hydra'],
        'john': [r'john', r'johntheripper'],
        'hashcat': [r'hashcat'],
        'nikto': [r'nikto'],
        'gobuster': [r'gobuster', r'ffuf', r'feroxbuster'],
        'wpscan': [r'wpscan'],
        'burp': [r'burp', r'zap'],
        'wireshark': [r'wireshark', r'tshark'],
        'tcpdump': [r'tcpdump'],
        'netcat': [r'netcat', r'nc\b'],
        'python': [r'python', r'python3', r'pip'],
        'bash': [r'bash', r'sh\b', r'zsh'],
        'curl': [r'curl', r'wget'],
        'git': [r'git'],
        'apt': [r'apt', r'apt-get', r'yum', r'dnf'],
    }
    
    for tool, patterns in tool_patterns.items():
        for pattern in patterns:
            if re.search(pattern, cmd_lower):
                return tool
    
    return ''


def process_dataset(data_path: Path) -> Dict[str, Any]:
    """Process dataset with enhanced extraction"""
    
    db = ObsidianDB(Path('data/obsidian.db'))
    
    # Discover files
    logger.info(f"Discovering files in {data_path}")
    discovery = FileDiscovery(data_path)
    structure = discovery.discover()
    
    logger.info(f"Found {structure.total_files} files")
    
    # Parser map
    parser_map = {
        'uat': UATParser,
        'bt_jsonl': BTJsonLParser,
        'sensor': SensorParser,
        'auth': AuthParser,
        'syslog': SyslogParser,
        'hacktools': HackToolsParser,
        'zeek': ZeekParser,
        'suricata': SuricataParser,
        'video': VideoParser,
        'cast': CastParser,
        'pcap': PcapParser,
    }
    
    parsers_needed = discovery.get_parsers_needed()
    
    total_events = 0
    commands_extracted = 0
    
    for parser_name, file_list in parsers_needed.items():
        if not file_list:
            continue
        
        parser_class = parser_map.get(parser_name)
        if not parser_class:
            continue
        
        logger.info(f"Processing {parser_name}: {len(file_list)} files")
        
        parser = parser_class()
        
        for file_path in file_list:
            try:
                events = list(parser.parse(file_path))
                
                # Enhanced: Extract commands from raw_data
                for event in events:
                    event_dict = vars(event) if hasattr(event, '__dict__') else event
                    
                    # Extract command if not set
                    if not event_dict.get('command'):
                        raw = event_dict.get('raw_data', '')
                        if raw:
                            cmd = extract_command_from_raw(raw, parser_name)
                            if cmd:
                                event_dict['command'] = cmd
                                commands_extracted += 1
                    
                    # Detect tool from command if not set
                    if not event_dict.get('tool') and event_dict.get('command'):
                        tool = extract_tool_from_command(event_dict['command'])
                        if tool:
                            event_dict['tool'] = tool
                
                if events:
                    db.insert_events_batch(events)
                    total_events += len(events)
                    
            except Exception as e:
                logger.error(f"Error parsing {file_path}: {e}")
    
    stats = db.get_stats()
    stats['commands_extracted'] = commands_extracted
    
    db.close()
    
    return stats


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='GOD EYE - Enhanced Data Processor')
    parser.add_argument('input', type=Path, help='Path to dataset directory')
    args = parser.parse_args()
    
    logger.info("="*60)
    logger.info("GOD EYE - Enhanced Data Processor")
    logger.info("="*60)
    
    stats = process_dataset(args.input)
    
    logger.info("="*60)
    logger.info("PROCESSING COMPLETE")
    logger.info("="*60)
    logger.info(f"Total Events: {stats.get('total_events', 0)}")
    logger.info(f"Unique Hosts: {stats.get('unique_hosts', 0)}")
    logger.info(f"Unique Tools: {stats.get('unique_tools', 0)}")
    logger.info(f"Commands Extracted: {stats.get('commands_extracted', 0)}")
    logger.info("="*60)
