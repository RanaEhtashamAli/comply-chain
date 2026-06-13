"""
GLBA §314.4(c)(6) — Customer Information Disposal

Provides secure file deletion (DoD 5220.22-M style overwrite) and a
retention-policy enforcer that audits disposal events.
"""

import logging
import os
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


class DataDisposal:
    """
    Implements GLBA §314.4(c)(6): Customer Information Disposal.

    Securely deletes files by overwriting their contents before unlinking,
    then appends a record to the audit log passed in at construction.

    Args:
        auditor: Optional GLBAAuditor instance. When provided, every
                 disposal event is logged to the Merkle-chained audit trail.
        passes: Number of overwrite passes (default 3 — DoD 5220.22-M).
    """

    def __init__(self, auditor=None, passes: int = 3):
        self._auditor = auditor
        self._passes = passes

    def dispose(self, path: Path, reason: str = "retention_policy") -> bool:
        """
        Securely delete *path* by overwriting then unlinking.

        Returns True on success, False if the file does not exist.
        """
        path = Path(path)
        if not path.exists():
            logger.warning(f"Disposal requested for non-existent path: {path}")
            return False

        size = path.stat().st_size
        try:
            with open(path, 'r+b') as f:
                for _ in range(self._passes):
                    f.seek(0)
                    f.write(secrets.token_bytes(size))
                    f.flush()
                    os.fsync(f.fileno())
            path.unlink()
            logger.info(f"Securely disposed: {path} ({size} bytes, {self._passes} passes)")
        except Exception as e:
            logger.error(f"Secure disposal failed for {path}: {e}")
            return False

        self._audit(path, size, reason)
        return True

    def enforce_retention(
        self,
        directory: Path,
        max_age_days: int,
        pattern: str = '*',
        dry_run: bool = False,
    ) -> List[Path]:
        """
        Delete files in *directory* matching *pattern* older than *max_age_days*.

        Args:
            directory: Directory to scan.
            max_age_days: Files older than this many days are disposed.
            pattern: Glob pattern (default '*' matches all files).
            dry_run: If True, return paths that *would* be deleted without deleting.

        Returns:
            List of paths that were (or would be) disposed.
        """
        directory = Path(directory)
        if not directory.exists():
            return []

        cutoff = datetime.now() - timedelta(days=max_age_days)
        disposed: List[Path] = []

        for path in directory.glob(pattern):
            if not path.is_file():
                continue
            mtime = datetime.fromtimestamp(path.stat().st_mtime)
            if mtime < cutoff:
                if dry_run:
                    disposed.append(path)
                else:
                    if self.dispose(path, reason=f"retention_policy:{max_age_days}d"):
                        disposed.append(path)

        if dry_run:
            logger.info(f"Dry-run retention scan: {len(disposed)} files would be disposed")
        else:
            logger.info(f"Retention enforcement complete: {len(disposed)} files disposed")

        return disposed

    def _audit(self, path: Path, size: int, reason: str) -> None:
        if self._auditor is None:
            return
        try:
            self._auditor.log_transaction(
                tx_data={
                    'event': 'data_disposal',
                    'path': str(path),
                    'size_bytes': size,
                    'passes': self._passes,
                    'reason': reason,
                    'timestamp': datetime.now().isoformat(),
                },
                signature=b'disposal_event',
            )
        except Exception as e:
            logger.warning(f"Could not log disposal event to audit chain: {e}")
