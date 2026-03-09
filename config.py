"""
OBSIDIAN - Cybersecurity Scenario Analytics Platform
Configuration Module
"""

import os
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

@dataclass
class Config:
    """Main configuration class for OBSIDIAN"""
    
    # Paths
    BASE_DIR: Path = Path(__file__).parent
    DATA_DIR: Path = BASE_DIR / "data"
    OUTPUT_DIR: Path = BASE_DIR / "output"
    DB_PATH: Path = DATA_DIR / "obsidian.db"
    
    # Storage
    STORAGE_TYPE: str = "sqlite"  # sqlite, neo4j, pinecone
    NEO4J_URI: str = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    NEO4J_USER: str = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD: str = os.getenv("NEO4J_PASSWORD", "password")
    PINECONE_API_KEY: str = os.getenv("PINECONE_API_KEY", "")
    PINECONE_ENV: str = os.getenv("PINECONE_ENV", "us-west1")
    
    # API
    API_HOST: str = os.getenv("API_HOST", "0.0.0.0")
    API_PORT: int = int(os.getenv("API_PORT", "8000"))
    API_DEBUG: bool = os.getenv("API_DEBUG", "true").lower() == "true"
    
    # Processing
    MAX_WORKERS: int = int(os.getenv("MAX_WORKERS", "4"))
    BATCH_SIZE: int = int(os.getenv("BATCH_SIZE", "1000"))
    
    # AI/ML
    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "openai")  # openai, anthropic, local
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
    LOCAL_LLM_URL: str = os.getenv("LOCAL_LLM_URL", "http://localhost:11434")
    
    # Logging
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    LOG_FILE: Path = BASE_DIR / "logs" / "obsidian.log"
    
    # Supported file types
    SUPPORTED_COMPRESSION: tuple = (".tar", ".tar.gz", ".tgz", ".zip", ".rar", ".7z")
    SUPPORTED_LOGS: tuple = (".log", ".tsv", ".json", ".jsonl", ".syslog")
    SUPPORTED_NETWORK: tuple = (".pcap", ".pcapng", ".cap")
    SUPPORTED_VIDEO: tuple = (".cast", ".ogv", ".mp4")
    
    def __post_init__(self):
        """Create directories if they don't exist"""
        self.DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        self.LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

# Global config instance
config = Config()
