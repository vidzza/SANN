"""
OBSIDIAN - Storage Module
Simplified SQLite database manager
"""

import json
import logging
import sqlite3
from pathlib import Path
from typing import Iterator, List, Dict, Any, Optional, Union
from datetime import datetime
from dataclasses import dataclass, asdict, is_dataclass

logger = logging.getLogger(__name__)

class ObsidianDB:
    """SQLite database manager for OBSIDIAN events"""
    
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn: Optional[sqlite3.Connection] = None
        self._init_db()
    
    def _init_db(self):
        """Initialize database schema"""
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        
        cursor = self.conn.cursor()
        
        # Simplified events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                scenario_id TEXT,
                timestamp_utc TEXT,
                source_type TEXT,
                source_file TEXT,
                source_host TEXT,
                src_ip TEXT,
                src_port INTEGER,
                dest_ip TEXT,
                dest_port INTEGER,
                protocol TEXT,
                user TEXT,
                action_category TEXT,
                action_name TEXT,
                tool TEXT,
                result TEXT,
                command TEXT,
                arguments TEXT,
                working_dir TEXT,
                process_id INTEGER,
                alert_type TEXT,
                alert_severity INTEGER,
                detection_source TEXT,
                http_method TEXT,
                url TEXT,
                user_agent TEXT,
                http_status INTEGER,
                raw_data TEXT,
                extra_data TEXT
            )
        ''')
        
        # Indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp_utc)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scenario ON events(scenario_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_tool ON events(tool)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_action ON events(action_name)')
        
        self.conn.commit()
        logger.info(f"Database initialized at {self.db_path}")
    
    def _event_to_dict(self, event) -> Dict:
        """Convert event to dict, handling both dicts and dataclasses"""
        if is_dataclass(event):
            return asdict(event)
        return event
    
    def insert_events_batch(self, events: Iterator, batch_size: int = 1000):
        """Insert events in batches"""
        assert self.conn is not None
        cursor: sqlite3.Cursor = self.conn.cursor()
        batch = []
        
        for event in events:
            # Convert to dict if needed
            event_dict = self._event_to_dict(event)
            
            batch.append((
                event_dict.get('event_id', ''),
                event_dict.get('scenario_id', ''),
                event_dict.get('timestamp_utc', ''),
                event_dict.get('source_type', ''),
                event_dict.get('source_file', ''),
                event_dict.get('source_host', ''),
                event_dict.get('src_ip', ''),
                event_dict.get('src_port', 0),
                event_dict.get('dest_ip', ''),
                event_dict.get('dest_port', 0),
                event_dict.get('protocol', ''),
                event_dict.get('user', ''),
                event_dict.get('action_category', ''),
                event_dict.get('action_name', ''),
                event_dict.get('tool', ''),
                event_dict.get('result', ''),
                event_dict.get('command', ''),
                event_dict.get('arguments', ''),
                event_dict.get('working_dir', ''),
                event_dict.get('process_id', 0),
                event_dict.get('alert_type', ''),
                event_dict.get('alert_severity', 0),
                event_dict.get('detection_source', ''),
                event_dict.get('http_method', ''),
                event_dict.get('url', ''),
                event_dict.get('user_agent', ''),
                event_dict.get('http_status', 0),
                event_dict.get('raw_data', ''),
                json.dumps(event_dict.get('parsed_data', {}))
            ))
            
            if len(batch) >= batch_size:
                self._insert_batch(cursor, batch)
                batch = []
        
        if batch:
            self._insert_batch(cursor, batch)
        
        self.conn.commit()
    
    def _insert_batch(self, cursor, batch: List[tuple]):
        """Insert a batch of events"""
        cursor.executemany('''
            INSERT OR REPLACE INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', batch)
    
    def query(self, sql: str, params: tuple = ()) -> List[Dict]:
        """Execute a query"""
        assert self.conn is not None
        cursor: sqlite3.Cursor = self.conn.cursor()
        cursor.execute(sql, params)
        return [dict(row) for row in cursor.fetchall()]
    
    def get_events(self, filters: Optional[Dict] = None, limit: int = 100) -> List[Dict]:
        """Get events with optional filters"""
        sql = "SELECT * FROM events WHERE 1=1"
        params = []
        
        if filters:
            for key, value in filters.items():
                sql += f" AND {key} = ?"
                params.append(value)
        
        sql += " ORDER BY timestamp_utc DESC LIMIT ?"
        params.append(limit)
        
        return self.query(sql, tuple(params))
    
    def get_unique_tools(self, scenario_id: Optional[str] = None) -> List[str]:
        """Get unique tools"""
        sql = "SELECT DISTINCT tool FROM events WHERE tool IS NOT NULL AND tool != ''"
        if scenario_id:
            sql += " AND scenario_id = ?"
            return [row['tool'] for row in self.query(sql, (scenario_id,))]
        return [row['tool'] for row in self.query(sql)]
    
    def get_unique_hosts(self, scenario_id: Optional[str] = None) -> List[str]:
        """Get unique hosts"""
        sql = "SELECT DISTINCT source_host FROM events WHERE source_host IS NOT NULL AND source_host != ''"
        if scenario_id:
            sql += " AND scenario_id = ?"
            return [row['source_host'] for row in self.query(sql, (scenario_id,))]
        return [row['source_host'] for row in self.query(sql)]
    
    def get_timeline(self, scenario_id: Optional[str] = None, limit: int = 1000) -> List[Dict]:
        """Get timeline"""
        sql = "SELECT * FROM events WHERE timestamp_utc IS NOT NULL AND timestamp_utc != ''"
        params = []
        if scenario_id:
            sql += " AND scenario_id = ?"
            params.append(scenario_id)
        sql += " ORDER BY timestamp_utc ASC LIMIT ?"
        params.append(limit)
        return self.query(sql, tuple(params))
    
    def get_alerts(self, scenario_id: Optional[str] = None) -> List[Dict]:
        """Get alerts"""
        sql = "SELECT * FROM events WHERE alert_type IS NOT NULL AND alert_type != ''"
        params = []
        if scenario_id:
            sql += " AND scenario_id = ?"
            params.append(scenario_id)
        sql += " ORDER BY timestamp_utc ASC"
        return self.query(sql, tuple(params))
    
    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        stats = {}
        stats['total_events'] = self.query("SELECT COUNT(*) as count FROM events")[0]['count']
        
        type_counts = self.query("SELECT source_type, COUNT(*) as count FROM events GROUP BY source_type")
        stats['events_by_type'] = {row['source_type']: row['count'] for row in type_counts}
        
        stats['unique_scenarios'] = len(self.query("SELECT DISTINCT scenario_id FROM events WHERE scenario_id IS NOT NULL AND scenario_id != ''"))
        stats['unique_hosts'] = len(self.query("SELECT DISTINCT source_host FROM events WHERE source_host IS NOT NULL AND source_host != ''"))
        stats['unique_tools'] = len(self.query("SELECT DISTINCT tool FROM events WHERE tool IS NOT NULL AND tool != ''"))
        
        return stats
    
    def close(self):
        if self.conn:
            self.conn.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
