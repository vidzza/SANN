"""
OBSIDIAN - Ingestor Module
"""

from .auto_extractor import AutoExtractor, extract_dataset, ExtractionResult
from .file_discovery import FileDiscovery, DatasetStructure, FileInfo

__all__ = [
    'AutoExtractor',
    'extract_dataset', 
    'ExtractionResult',
    'FileDiscovery',
    'DatasetStructure',
    'FileInfo',
]
