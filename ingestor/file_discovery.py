"""
OBSIDIAN - File Discovery Module
Find and categorize files in extracted datasets
"""

import os
import logging
from pathlib import Path
from typing import List, Dict, Optional, Generator
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger(__name__)

@dataclass
class FileInfo:
    """Information about a discovered file"""
    path: Path
    relative_path: str
    size: int
    file_type: str
    category: str
    
@dataclass 
class DatasetStructure:
    """Structure of a discovered dataset"""
    root_path: Path
    total_files: int = 0
    total_size: int = 0
    files_by_category: Dict[str, List[FileInfo]] = field(default_factory=dict)
    files_by_type: Dict[str, List[FileInfo]] = field(default_factory=dict)
    scenarios: List[str] = field(default_factory=list)
    hosts: List[str] = field(default_factory=list)

class FileDiscovery:
    """Discover and categorize files in datasets"""
    
    # File type mappings
    FILE_CATEGORIES = {
        'activity': ['tsv', 'cast', 'ogv'],
        'behavior': ['jsonl', 'log'],
        'auth': ['auth.log'],
        'system': ['syslog'],
        'network': ['pcap', 'pcapng', 'cap'],
        'ids': ['eve.json', 'fast.log', 'suricata.log'],
        'zeek': ['conn.log', 'ssh.log', 'dns.log', 'http.log', 'notice.log', 'files.log'],
        'sensor': ['sensor.log'],
        'inventory': ['vm_list', 'vmlist'],
        'metadata': ['scenario'],
    }
    
    FILE_EXTENSIONS = {
        # Activity
        '.tsv': 'uat',
        '.cast': 'cast',
        '.ogv': 'video',
        
        # Behavior
        '.jsonl': 'jsonl',
        '.bt.log': 'bt_log',
        
        # Logs
        '.log': 'log',
        
        # Network
        '.pcap': 'pcap',
        '.pcapng': 'pcap',
        '.cap': 'pcap',
        
        # JSON
        '.json': 'json',
        
        # Config/Inventory
        '.vm_list': 'vm_list',
    }
    
    # Scenario patterns
    SCENARIO_PATTERNS = [
        'training',
        'ckc1',
        'ckc2',
        'ckc3',
        'scenario',
    ]
    
    # Host patterns
    HOST_PATTERNS = [
        'atkr-',      # Attacker
        'dmz-',       # DMZ
        'int-',       # Internal
        'sec-',       # Security
        'mgmt-',      # Management
        'workstation',
    ]
    
    def __init__(self, root_path: Path):
        self.root_path = Path(root_path)
        
    def discover(self) -> DatasetStructure:
        """
        Discover all files in the dataset
        
        Returns:
            DatasetStructure with categorized files
        """
        structure = DatasetStructure(root_path=self.root_path)
        
        logger.info(f"Discovering files in {self.root_path}")
        
        for file_path in self.root_path.rglob('*'):
            if not file_path.is_file():
                continue
                
            # Skip hidden files
            if file_path.name.startswith('.'):
                continue
                
            file_info = self._analyze_file(file_path)
            if file_info:
                # Add to category dict
                if file_info.category not in structure.files_by_category:
                    structure.files_by_category[file_info.category] = []
                structure.files_by_category[file_info.category].append(file_info)
                
                # Add to type dict
                if file_info.file_type not in structure.files_by_type:
                    structure.files_by_type[file_info.file_type] = []
                structure.files_by_type[file_info.file_type].append(file_info)
                
                # Extract scenario
                scenario = self._extract_scenario(file_path)
                if scenario and scenario not in structure.scenarios:
                    structure.scenarios.append(scenario)
                
                # Extract host
                host = self._extract_host(file_path)
                if host and host not in structure.hosts:
                    structure.hosts.append(host)
                
                structure.total_files += 1
                structure.total_size += file_info.size
        
        logger.info(f"Discovered {structure.total_files} files ({structure.total_size / 1024 / 1024:.2f} MB)")
        
        return structure
    
    def _analyze_file(self, file_path: Path) -> Optional[FileInfo]:
        """Analyze a single file and return its info"""
        try:
            size = file_path.stat().st_size
        except OSError:
            size = 0
            
        relative_path = file_path.relative_to(self.root_path)
        
        # Determine file type
        ext = file_path.suffix.lower()
        file_type = self.FILE_EXTENSIONS.get(ext, ext.lstrip('.') or 'unknown')
        
        # Determine category
        category = self._determine_category(file_path, ext)
        
        return FileInfo(
            path=file_path,
            relative_path=str(relative_path),
            size=size,
            file_type=file_type,
            category=category
        )
    
    def _determine_category(self, file_path: Path, ext: str) -> str:
        """Determine the category of a file"""
        filename = file_path.name.lower()
        parent = file_path.parent.name.lower()
        
        # Check parent directory first (for zeek, suricata, etc.)
        for category, patterns in self.FILE_CATEGORIES.items():
            if parent in patterns or any(p in parent for p in patterns):
                return category
        
        # Check file extension
        for category, extensions in self.FILE_CATEGORIES.items():
            if ext in extensions or any(ext.replace('.', '') == e.replace('.', '') for e in extensions):
                return category
        
        # Check filename
        if 'auth' in filename:
            return 'auth'
        if 'syslog' in filename:
            return 'system'
        if 'bt.' in filename:
            return 'behavior'
        if 'sensor' in filename:
            return 'sensor'
        if 'hacktools' in filename:
            return 'activity'
        if 'apt' in filename:
            return 'activity'
        if 'vm_list' in filename or filename.startswith('vmlist'):
            return 'inventory'
        if '.scenario' in filename:
            return 'metadata'
            
        return 'other'
    
    def _extract_scenario(self, file_path: Path) -> Optional[str]:
        """Extract scenario ID from file path"""
        path_str = str(file_path)
        
        for pattern in self.SCENARIO_PATTERNS:
            if pattern in path_str:
                # Try to extract the scenario identifier
                parts = path_str.split('/')
                for part in parts:
                    if pattern in part and part != pattern:
                        return part
                        
        return None
    
    def _extract_host(self, file_path: Path) -> Optional[str]:
        """Extract hostname from file path"""
        path_str = str(file_path)
        
        for pattern in self.HOST_PATTERNS:
            if pattern in path_str:
                # Extract the host from path like: P003/user2003/ckc1/1/atkr-kali/auth.log
                parts = path_str.split('/')
                for part in parts:
                    if pattern in part:
                        return part
                        
        return None
    
    def get_files_by_category(self, category: str) -> List[Path]:
        """Get all files of a specific category"""
        structure = self.discover()
        return [f.path for f in structure.files_by_category.get(category, [])]
    
    def get_files_by_type(self, file_type: str) -> List[Path]:
        """Get all files of a specific type"""
        structure = self.discover()
        return [f.path for f in structure.files_by_type.get(file_type, [])]
    
    def get_parsers_needed(self) -> Dict[str, List[Path]]:
        """
        Get mapping of parsers to files that need them
        
        Returns:
            Dict mapping parser name to list of file paths
        """
        structure = self.discover()
        
        parsers_needed = {
            'uat': [],
            'cast': [],
            'video': [],
            'bt_jsonl': [],
            'bt_log': [],
            'auth': [],
            'syslog': [],
            'sensor': [],
            'hacktools': [],
            'apt': [],
            'zeek': [],
            'suricata': [],
            'pcap': [],
            'vm': [],
            'scenario': [],
        }
        
        for file_type, files in structure.files_by_type.items():
            for file_info in files:
                if file_type == 'uat':
                    parsers_needed['uat'].append(file_info.path)
                elif file_type == 'cast':
                    parsers_needed['cast'].append(file_info.path)
                elif file_type == 'video':
                    parsers_needed['video'].append(file_info.path)
                elif file_type == 'jsonl':
                    parsers_needed['bt_jsonl'].append(file_info.path)
                elif file_type == 'bt_log':
                    parsers_needed['bt_log'].append(file_info.path)
                elif file_type == 'sensor':
                    parsers_needed['sensor'].append(file_info.path)
                elif 'hacktools' in file_info.relative_path:
                    parsers_needed['hacktools'].append(file_info.path)
                elif 'apt' in file_info.relative_path:
                    parsers_needed['apt'].append(file_info.path)
                elif 'zeek' in file_info.relative_path:
                    parsers_needed['zeek'].append(file_info.path)
                elif 'suricata' in file_info.relative_path:
                    parsers_needed['suricata'].append(file_info.path)
                elif file_type == 'pcap':
                    parsers_needed['pcap'].append(file_info.path)
                elif file_type == 'vm_list':
                    parsers_needed['vm'].append(file_info.path)
                elif 'scenario' in file_info.relative_path:
                    parsers_needed['scenario'].append(file_info.path)
                elif file_type == 'log':
                    # Determine if auth or syslog
                    if 'auth' in file_info.relative_path:
                        parsers_needed['auth'].append(file_info.path)
                    else:
                        parsers_needed['syslog'].append(file_info.path)
        
        return parsers_needed
