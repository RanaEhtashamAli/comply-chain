"""
GLBA §314.4(c)(2) — Data Inventory and Classification

Scans directories for files containing customer PII and produces a
data map that can be used as evidence of a GLBA-compliant data inventory.
"""

import re
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# PII detection patterns
_PII_PATTERNS: Dict[str, re.Pattern] = {
    'ssn':         re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    'credit_card': re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'),
    'email':       re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'),
    'phone':       re.compile(r'\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'),
    'routing_aba': re.compile(r'\b[0-9]{9}\b'),   # US ABA routing number (9 digits)
}

_BINARY_EXTENSIONS = {'.pkl', '.bin', '.exe', '.so', '.pyc', '.jpg', '.png', '.pdf'}


@dataclass
class FileRecord:
    path: str
    size_bytes: int
    pii_types_found: List[str]
    classification: str   # 'sensitive' | 'restricted' | 'public'
    last_modified: str


@dataclass
class DataInventoryReport:
    scanned_at: str
    root_directory: str
    total_files: int
    sensitive_files: int
    restricted_files: int
    public_files: int
    records: List[FileRecord] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            'scanned_at': self.scanned_at,
            'root_directory': self.root_directory,
            'total_files': self.total_files,
            'sensitive_files': self.sensitive_files,
            'restricted_files': self.restricted_files,
            'public_files': self.public_files,
            'records': [
                {
                    'path': r.path,
                    'size_bytes': r.size_bytes,
                    'pii_types_found': r.pii_types_found,
                    'classification': r.classification,
                    'last_modified': r.last_modified,
                }
                for r in self.records
            ],
        }


class DataInventoryScanner:
    """
    Implements GLBA §314.4(c)(2): Data Inventory and Classification.

    Walks a directory tree, detects PII patterns in text files, classifies
    each file, and produces a DataInventoryReport.
    """

    def __init__(self, max_file_size_mb: float = 10.0):
        self._max_bytes = int(max_file_size_mb * 1024 * 1024)

    def scan(self, directory: Path, extensions: Optional[List[str]] = None) -> DataInventoryReport:
        """
        Scan *directory* for files containing customer PII.

        Args:
            directory: Root path to scan.
            extensions: Whitelist of file extensions (e.g. ['.txt', '.json']).
                        When None all non-binary extensions are checked.

        Returns:
            DataInventoryReport
        """
        directory = Path(directory)
        if not directory.exists():
            raise FileNotFoundError(f"Directory not found: {directory}")

        records: List[FileRecord] = []
        sensitive = restricted = public = 0

        for path in directory.rglob('*'):
            if not path.is_file():
                continue
            if path.suffix.lower() in _BINARY_EXTENSIONS:
                continue
            if extensions and path.suffix.lower() not in extensions:
                continue
            if path.stat().st_size > self._max_bytes:
                logger.debug(f"Skipping large file: {path}")
                continue

            pii_found = self._detect_pii(path)
            classification = self._classify(pii_found)

            if classification == 'sensitive':
                sensitive += 1
            elif classification == 'restricted':
                restricted += 1
            else:
                public += 1

            records.append(FileRecord(
                path=str(path),
                size_bytes=path.stat().st_size,
                pii_types_found=pii_found,
                classification=classification,
                last_modified=datetime.fromtimestamp(path.stat().st_mtime).isoformat(),
            ))

        total = sensitive + restricted + public
        logger.info(f"Data inventory scan complete: {total} files ({sensitive} sensitive)")

        return DataInventoryReport(
            scanned_at=datetime.now().isoformat(),
            root_directory=str(directory),
            total_files=total,
            sensitive_files=sensitive,
            restricted_files=restricted,
            public_files=public,
            records=records,
        )

    def _detect_pii(self, path: Path) -> List[str]:
        """Return list of PII type names found in *path*."""
        try:
            text = path.read_text(errors='ignore')
        except Exception:
            return []
        found = []
        for name, pattern in _PII_PATTERNS.items():
            if pattern.search(text):
                found.append(name)
        return found

    def _classify(self, pii_types: List[str]) -> str:
        if any(t in pii_types for t in ('ssn', 'credit_card', 'routing_aba')):
            return 'sensitive'
        if pii_types:
            return 'restricted'
        return 'public'

    def save_report(self, report: DataInventoryReport, output_path: Path) -> None:
        """Persist inventory report as JSON."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(report.to_dict(), indent=2))
        logger.info(f"Data inventory report saved to {output_path}")
