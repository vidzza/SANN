#!/usr/bin/env python3
"""
OBSIDIAN - Cybersecurity Scenario Analytics Platform
Main entry point
"""

import sys
import os
import logging
import argparse
from pathlib import Path
from typing import List, Optional

# Add code directory to path
sys.path.insert(0, str(Path(__file__).parent))

from config import config
from ingestor import AutoExtractor, FileDiscovery
from storage.database import ObsidianDB

# Import parsers
from parsers.base import BaseParser
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

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ObsidianEngine:
    """
    Main OBSIDIAN processing engine
    """
    
    def __init__(self, data_dir: Path = None):
        self.data_dir = data_dir or config.DATA_DIR
        self.db = ObsidianDB(config.DB_PATH)
        self.parsers: List[BaseParser] = self._register_parsers()
    
    def _register_parsers(self) -> List[BaseParser]:
        """Register all available parsers"""
        return [
            UATParser(),
            BTJsonLParser(),
            SensorParser(),
            AuthParser(),
            SyslogParser(),
            HackToolsParser(),
            ZeekParser(),
            SuricataParser(),
            VideoParser(),
            CastParser(),
            PcapParser(),
        ]
    
    def process_dataset(self, dataset_path: Path) -> dict:
        """
        Process a complete dataset
        
        Args:
            dataset_path: Path to compressed dataset (.tar.gz, .zip, etc.)
            
        Returns:
            Processing statistics
        """
        logger.info(f"Processing dataset: {dataset_path}")
        
        stats = {
            'extraction': {},
            'files_discovered': {},
            'events_parsed': 0,
            'parsers_used': {},
        }
        
        # Step 1: Extract dataset
        logger.info("Step 1: Extracting dataset...")
        extractor = AutoExtractor(self.data_dir / "extracted")
        
        try:
            extracted_path = extractor.extract_recursive(dataset_path)
            stats['extraction'] = {
                'success': True,
                'path': str(extracted_path),
            }
            logger.info(f"Extracted to: {extracted_path}")
        except Exception as e:
            logger.error(f"Extraction failed: {e}")
            stats['extraction'] = {
                'success': False,
                'error': str(e)
            }
            return stats
        
        # Step 2: Discover files
        logger.info("Step 2: Discovering files...")
        discovery = FileDiscovery(extracted_path)
        structure = discovery.discover()
        
        stats['files_discovered'] = {
            'total': structure.total_files,
            'total_size_mb': structure.total_size / 1024 / 1024,
            'scenarios': structure.scenarios,
            'hosts': structure.hosts,
            'by_category': {k: len(v) for k, v in structure.files_by_category.items()},
            'by_type': {k: len(v) for k, v in structure.files_by_type.items()},
        }
        
        logger.info(f"Found {structure.total_files} files")
        logger.info(f"Scenarios: {structure.scenarios}")
        logger.info(f"Hosts: {len(structure.hosts)}")
        
        # Step 3: Parse files
        logger.info("Step 3: Parsing files...")
        parsers_needed = discovery.get_parsers_needed()
        
        total_events = 0
        
        for parser_name, file_list in parsers_needed.items():
            if not file_list:
                continue
            
            logger.info(f"  {parser_name}: {len(file_list)} files")
            
            # Find appropriate parser
            parser = self._find_parser(parser_name)
            if not parser:
                logger.warning(f"No parser found for: {parser_name}")
                continue
            
            for file_path in file_list:
                try:
                    events = parser.parse(file_path)
                    self.db.insert_events_batch(events)
                    total_events += parser.events_parsed
                    stats['parsers_used'][parser_name] = parser.events_parsed
                except Exception as e:
                    logger.error(f"Error parsing {file_path}: {e}")
        
        stats['events_parsed'] = total_events
        
        # Step 4: Get final stats
        logger.info("Step 4: Computing statistics...")
        final_stats = self.db.get_stats()
        stats['database'] = final_stats
        
        logger.info(f"Total events in database: {final_stats.get('total_events', 0)}")
        
        return stats
    
    def _find_parser(self, parser_name: str) -> Optional[BaseParser]:
        """Find parser by name"""
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
        
        parser_class = parser_map.get(parser_name)
        if parser_class:
            return parser_class()
        return None
    
    def query(self, sql: str) -> List[dict]:
        """Execute custom query"""
        return self.db.query(sql)
    
    def get_timeline(self, scenario_id: Optional[str] = None) -> List[dict]:
        """Get event timeline"""
        return self.db.get_timeline(scenario_id)
    
    def get_tools(self, scenario_id: Optional[str] = None) -> List[str]:
        """Get unique tools used"""
        return self.db.get_unique_tools(scenario_id)
    
    def get_hosts(self, scenario_id: Optional[str] = None) -> List[str]:
        """Get unique hosts"""
        return self.db.get_unique_hosts(scenario_id)
    
    def get_alerts(self, scenario_id: Optional[str] = None) -> List[dict]:
        """Get security alerts"""
        return self.db.get_alerts(scenario_id)
    
    def close(self):
        """Close database connection"""
        self.db.close()


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='OBSIDIAN - Cybersecurity Analytics Platform')
    parser.add_argument('input', type=Path, help='Path to dataset (compressed file or extracted directory)')
    parser.add_argument('--output-dir', type=Path, default=config.DATA_DIR, help='Output directory')
    parser.add_argument('--list-parsers', action='store_true', help='List available parsers')
    parser.add_argument('--query', type=str, help='Execute SQL query')
    parser.add_argument('--timeline', action='store_true', help='Show event timeline')
    parser.add_argument('--tools', action='store_true', help='Show tools used')
    parser.add_argument('--hosts', action='store_true', help='Show hosts')
    parser.add_argument('--alerts', action='store_true', help='Show security alerts')
    parser.add_argument('--stats', action='store_true', help='Show database statistics')
    
    args = parser.parse_args()
    
    engine = ObsidianEngine(args.output_dir)
    
    try:
        if args.list_parsers:
            print("Available parsers:")
            print("  - UATParser (User Activity Timeline)")
            print("  - BTJsonLParser (Behavior Tracking JSONL)")
            print("  - SensorParser (Sensor Logs)")
            print("  - AuthParser (Authentication Logs)")
            print("  - SyslogParser (System Logs)")
            print("  - HackToolsParser (HackTools Logs)")
            print("  - ZeekParser (Zeek Network Logs)")
            print("  - SuricataParser (Suricata IDS Logs)")
            return
        
        if args.input.exists():
            # Process dataset
            stats = engine.process_dataset(args.input)
            
            print("\n" + "="*60)
            print("OBSIDIAN PROCESSING COMPLETE")
            print("="*60)
            
            if 'extraction' in stats:
                ext = stats['extraction']
                print(f"\nExtraction: {'✓ SUCCESS' if ext.get('success') else '✗ FAILED'}")
                if ext.get('path'):
                    print(f"  Path: {ext['path']}")
            
            if 'files_discovered' in stats:
                fd = stats['files_discovered']
                print(f"\nFiles Discovered: {fd.get('total', 0)}")
                print(f"  Size: {fd.get('total_size_mb', 0):.2f} MB")
                print(f"  Scenarios: {', '.join(fd.get('scenarios', []))}")
            
            if 'events_parsed' in stats:
                print(f"\nEvents Parsed: {stats['events_parsed']}")
                for parser_name, count in stats.get('parsers_used', {}).items():
                    print(f"  {parser_name}: {count}")
            
            if 'database' in stats:
                db_stats = stats['database']
                print(f"\nDatabase Statistics:")
                print(f"  Total Events: {db_stats.get('total_events', 0)}")
                print(f"  Unique Hosts: {db_stats.get('unique_hosts', 0)}")
                print(f"  Unique Tools: {db_stats.get('unique_tools', 0)}")
                print(f"  Unique Users: {db_stats.get('unique_users', 0)}")
                print(f"  Unique IPs: {db_stats.get('unique_ips', 0)}")
            
            print("\n" + "="*60)
        
        else:
            print(f"Input path does not exist: {args.input}")
            print("Please provide a valid dataset path")
            return 1
        
        # Additional queries
        if args.timeline:
            print("\n--- EVENT TIMELINE (first 10) ---")
            timeline = engine.get_timeline()[:10]
            for event in timeline:
                ts = event.get('timestamp_utc', 'N/A')
                src = event.get('source_host', 'N/A')
                action = event.get('action_name', 'N/A')
                tool = event.get('tool', '')
                print(f"  {ts} | {src} | {action} | {tool}")
        
        if args.tools:
            print("\n--- TOOLS USED ---")
            tools = engine.get_tools()
            for tool in tools:
                print(f"  - {tool}")
        
        if args.hosts:
            print("\n--- HOSTS ---")
            hosts = engine.get_hosts()
            for host in hosts:
                print(f"  - {host}")
        
        if args.alerts:
            print("\n--- SECURITY ALERTS ---")
            alerts = engine.get_alerts()
            for alert in alerts[:20]:
                ts = alert.get('timestamp_utc', 'N/A')
                alert_type = alert.get('alert_type', 'N/A')
                severity = alert.get('alert_severity', 0)
                src_ip = alert.get('src_ip', 'N/A')
                print(f"  [{severity}] {ts} | {alert_type} | {src_ip}")
        
        if args.stats:
            print("\n--- DATABASE STATISTICS ---")
            result = engine.db.get_stats()
            for key, value in result.items():
                print(f"  {key}: {value}")
        
        if args.query:
            print(f"\n--- QUERY RESULT ---")
            result = engine.query(args.query)
            for row in result[:10]:
                print(f"  {row}")
        
    finally:
        engine.close()
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
