"""
OBSIDIAN - PCAP Parser
Parses .pcap and .pcapng network capture files
"""

import logging
import struct
from pathlib import Path
from typing import Iterator, Dict, Any
from datetime import datetime

from parsers.base import BaseParser, ParsedEvent

logger = logging.getLogger(__name__)


class PcapParser(BaseParser):
    """Parser for PCAP network capture files"""
    
    # PCAP magic numbers
    PCAP_MAGIC = 0xa1b2c3d4
    PCAP_MAGIC_SWAPPED = 0xd4c3b2a1
    PCAPNG_MAGIC = 0x0a0d0d0a
    
    def __init__(self):
        super().__init__()
        self.supported_extensions = ['.pcap', '.pcapng', '.cap']
    
    def can_parse(self, file_path: Path) -> bool:
        """Check if file is a PCAP file"""
        if file_path.suffix.lower() not in self.supported_extensions:
            return False
        
        # Check magic number
        try:
            with open(file_path, 'rb') as f:
                magic = struct.unpack('<I', f.read(4))[0]
                return magic in [self.PCAP_MAGIC, self.PCAP_MAGIC_SWAPPED, self.PCAPNG_MAGIC]
        except:
            return False
    
    def parse(self, file_path: Path) -> Iterator[ParsedEvent]:
        """
        Parse PCAP file to extract network capture metadata
        
        Note: Full packet parsing would require dpkt or scapy
        This extracts basic metadata from the capture file
        
        Yields:
            ParsedEvent with network capture metadata
        """
        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            return
        
        try:
            with open(file_path, 'rb') as f:
                # Read magic number
                magic = struct.unpack('<I', f.read(4))[0]
                
                # Determine byte order
                if magic == self.PCAP_MAGIC:
                    swapped = False
                elif magic == self.PCAP_MAGIC_SWAPPED:
                    swapped = True
                elif magic == self.PCAPNG_MAGIC:
                    # PCAPNG format - simplified parsing
                    swapped = False
                else:
                    logger.warning(f"Unknown PCAP format magic: {hex(magic)}")
                    return
                
                # Get file stats
                stat = file_path.stat()
                
                # Read rest of header
                f.seek(0)
                header = f.read(24)
                
                if magic == self.PCAPNG_MAGIC:
                    # Simplified PCAPNG handling
                    event = self._parse_pcapng(file_path, stat, swapped)
                else:
                    # PCAP handling
                    event = self._parse_pcap(file_path, stat, swapped)
                
                if event:
                    self.events_parsed += 1
                    yield event
                    
        except Exception as e:
            logger.error(f"Error parsing PCAP file {file_path}: {e}")
    
    def _parse_pcap(self, file_path: Path, stat, swapped: bool) -> ParsedEvent:
        """Parse PCAP file header"""
        try:
            with open(file_path, 'rb') as f:
                # Read global header (24 bytes)
                header = f.read(24)
                
                if len(header) < 24:
                    return None
                
                if swapped:
                    version_major = struct.unpack('>H', header[0:2])[0]
                    version_minor = struct.unpack('>H', header[2:4])[0]
                    snaplen = struct.unpack('>I', header[16:20])[0]
                    network = struct.unpack('>I', header[20:24])[0]
                else:
                    version_major = struct.unpack('<H', header[0:2])[0]
                    version_minor = struct.unpack('<H', header[2:4])[0]
                    snaplen = struct.unpack('<I', header[16:20])[0]
                    network = struct.unpack('<I', header[20:24])[0]
                
                # Count packets
                packet_count = 0
                try:
                    f.seek(24)
                    while True:
                        packet_header = f.read(16)
                        if len(packet_header) < 16:
                            break
                        
                        if swapped:
                            incl_len = struct.unpack('>I', packet_header[8:12])[0]
                        else:
                            incl_len = struct.unpack('<I', packet_header[8:12])[0]
                        
                        f.seek(f.tell() + incl_len)
                        packet_count += 1
                except:
                    pass
                
                event = ParsedEvent()
                event.source_type = 'pcap'
                event.source_file = str(file_path)
                event.source_host = self.extract_host_from_path(file_path)
                event.scenario_id = self.extract_scenario_from_path(file_path)
                
                event.action_name = 'network_capture'
                event.action_category = 'network'
                event.tool = 'tcpdump'
                
                # Network type mapping
                network_types = {1: 'Ethernet', 6: 'Token Ring', 7: 'ARP', 8: 'IP', 17: 'UDP', 6: 'TCP'}
                
                event.parsed_data = {
                    'format': 'pcap',
                    'version_major': version_major,
                    'version_minor': version_minor,
                    'snaplen': snaplen,
                    'network_type': network_types.get(network, f'Unknown({network})'),
                    'packet_count': packet_count,
                    'filename': file_path.name,
                    'size_bytes': stat.st_size
                }
                
                event.raw_data = f"filename={file_path.name}|packets={packet_count}|size={stat.st_size}|version={version_major}.{version_minor}"
                
                return event
                
        except Exception as e:
            logger.error(f"Error parsing PCAP header: {e}")
            return None
    
    def _parse_pcapng(self, file_path: Path, stat, swapped: bool) -> ParsedEvent:
        """Parse PCAPNG file metadata"""
        event = ParsedEvent()
        event.source_type = 'pcap'
        event.source_file = str(file_path)
        event.source_host = self.extract_host_from_path(file_path)
        event.scenario_id = self.extract_scenario_from_path(file_path)
        
        event.action_name = 'network_capture'
        event.action_category = 'network'
        event.tool = 'tcpdump'
        
        # PCAPNG format - just get basic info
        event.parsed_data = {
            'format': 'pcapng',
            'filename': file_path.name,
            'size_bytes': stat.st_size
        }
        
        event.raw_data = f"filename={file_path.name}|size={stat.st_size}|format=pcapng"
        
        return event
