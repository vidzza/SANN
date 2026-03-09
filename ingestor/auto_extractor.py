"""
OBSIDIAN - Auto Extractor Module
Automatically extract compressed files (tar, zip, etc.)
"""

import os
import tarfile
import zipfile
import logging
from pathlib import Path
from typing import Optional, List, Generator
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Optional imports - graceful degradation
try:
    import rarfile
    RARFILE_AVAILABLE = True
except ImportError:
    RARFILE_AVAILABLE = False
    
try:
    import py7zr
    PY7ZR_AVAILABLE = True
except ImportError:
    PY7ZR_AVAILABLE = False

@dataclass
class ExtractionResult:
    """Result of extraction operation"""
    success: bool
    output_path: Path
    files_extracted: int
    total_size: int
    error: Optional[str] = None

class AutoExtractor:
    """Automatically detect and extract compressed files"""
    
    SUPPORTED_FORMATS = {
        '.tar': 'tar',
        '.tar.gz': 'tar',
        '.tgz': 'tar',
        '.tar.bz2': 'tar',
        '.tar.xz': 'tar',
        '.tar.zst': 'tar',
        '.zip': 'zip',
        '.rar': 'rar',
        '.7z': '7z',
    }
    
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def detect_format(self, file_path: Path) -> str:
        """Detect compression format from file extension"""
        suffix = file_path.suffix.lower()
        
        # Check compound suffixes first
        if file_path.name.endswith('.tar.gz'):
            return 'tar'
        if file_path.name.endswith('.tar.bz2'):
            return 'tar'
        if file_path.name.endswith('.tar.xz'):
            return 'tar'
        if file_path.name.endswith('.tar.zst'):
            return 'tar'
        if file_path.name.endswith('.tgz'):
            return 'tar'
            
        return self.SUPPORTED_FORMATS.get(suffix, 'unknown')
    
    def extract(self, file_path: Path, preserve_structure: bool = True) -> ExtractionResult:
        """
        Extract compressed file to output directory
        
        Args:
            file_path: Path to compressed file
            preserve_structure: Keep original directory structure
            
        Returns:
            ExtractionResult with status and output path
        """
        if not file_path.exists():
            return ExtractionResult(
                success=False,
                output_path=file_path,
                files_extracted=0,
                total_size=0,
                error=f"File not found: {file_path}"
            )
        
        fmt = self.detect_format(file_path)
        
        if fmt == 'unknown':
            return ExtractionResult(
                success=False,
                output_path=file_path,
                files_extracted=0,
                total_size=0,
                error=f"Unknown format: {file_path.suffix}"
            )
        
        # Create output directory based on archive name
        if preserve_structure:
            output_path = self.output_dir / file_path.stem.replace('.tar', '')
        else:
            output_path = self.output_dir
            
        output_path.mkdir(parents=True, exist_ok=True)
        
        try:
            if fmt == 'tar':
                return self._extract_tar(file_path, output_path)
            elif fmt == 'zip':
                return self._extract_zip(file_path, output_path)
            elif fmt == 'rar':
                return self._extract_rar(file_path, output_path)
            elif fmt == '7z':
                return self._extract_7z(file_path, output_path)
        except Exception as e:
            logger.error(f"Extraction failed: {e}")
            return ExtractionResult(
                success=False,
                output_path=file_path,
                files_extracted=0,
                total_size=0,
                error=str(e)
            )
    
    def _extract_tar(self, file_path: Path, output_path: Path) -> ExtractionResult:
        """Extract tar archive"""
        files_extracted = 0
        total_size = 0
        
        with tarfile.open(file_path, 'r:*') as tar:
            tar.extractall(output_path)
            members = tar.getmembers()
            files_extracted = len(members)
            total_size = sum(m.size for m in members)
        
        logger.info(f"Extracted {files_extracted} files from {file_path.name}")
        
        return ExtractionResult(
            success=True,
            output_path=output_path,
            files_extracted=files_extracted,
            total_size=total_size
        )
    
    def _extract_zip(self, file_path: Path, output_path: Path) -> ExtractionResult:
        """Extract zip archive"""
        files_extracted = 0
        total_size = 0
        
        with zipfile.ZipFile(file_path, 'r') as zf:
            zf.extractall(output_path)
            files_extracted = len(zf.namelist())
            total_size = sum(info.file_size for info in zf.filelist)
        
        logger.info(f"Extracted {files_extracted} files from {file_path.name}")
        
        return ExtractionResult(
            success=True,
            output_path=output_path,
            files_extracted=files_extracted,
            total_size=total_size
        )
    
    def _extract_rar(self, file_path: Path, output_path: Path) -> ExtractionResult:
        """Extract rar archive"""
        if not RARFILE_AVAILABLE:
            return ExtractionResult(
                success=False,
                output_path=file_path,
                files_extracted=0,
                total_size=0,
                error="RAR support not available (install rarfile)"
            )
        with rarfile.RarFile(file_path, 'r') as rf:
            rf.extractall(output_path)
            files_extracted = len(rf.namelist())
            total_size = sum(info.file_size for info in rf.infolist())
        
        return ExtractionResult(
            success=True,
            output_path=output_path,
            files_extracted=files_extracted,
            total_size=total_size
        )
    
    def _extract_7z(self, file_path: Path, output_path: Path) -> ExtractionResult:
        """Extract 7z archive"""
        if not PY7ZR_AVAILABLE:
            return ExtractionResult(
                success=False,
                output_path=file_path,
                files_extracted=0,
                total_size=0,
                error="7z support not available (install py7zr)"
            )
        with py7zr.SevenZipFile(file_path, 'r') as sz:
            sz.extractall(output_path)
            files_extracted = len(sz.getnames())
        
        return ExtractionResult(
            success=True,
            output_path=output_path,
            files_extracted=files_extracted,
            total_size=0
        )
    
    def extract_recursive(self, file_path: Path) -> Path:
        """
        Extract and return the root extraction directory
        Handles nested archives
        """
        result = self.extract(file_path)
        
        if not result.success:
            raise RuntimeError(f"Extraction failed: {result.error}")
        
        # Check for nested archives and extract them too
        extracted_dir = result.output_path
        for item in extracted_dir.rglob('*'):
            if item.is_file():
                suffix = item.suffix.lower()
                if suffix in self.SUPPORTED_FORMATS:
                    try:
                        nested_result = self.extract(item)
                        if nested_result.success:
                            logger.info(f"Extracted nested archive: {item.name}")
                    except Exception as e:
                        logger.warning(f"Failed to extract nested {item.name}: {e}")
        
        return extracted_dir


def extract_dataset(dataset_path: Path, output_dir: Path) -> Path:
    """
    Convenience function to extract a dataset
    
    Args:
        dataset_path: Path to compressed dataset
        output_dir: Directory to extract to
        
    Returns:
        Path to extracted root directory
    """
    extractor = AutoExtractor(output_dir)
    return extractor.extract_recursive(dataset_path)
