"""
GLBA §314.4(c)(7) — Change Management Procedures

Records configuration and system changes to the Merkle-chained audit trail,
providing evidence that security impact of changes is tracked and reviewable.
"""

import json
import logging
import os
import socket
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class ChangeRecord:
    """Represents a single change event."""

    def __init__(
        self,
        change_type: str,
        component: str,
        description: str,
        changed_by: str,
        before: Optional[Any] = None,
        after: Optional[Any] = None,
        ticket_id: Optional[str] = None,
    ):
        self.change_type = change_type   # 'config' | 'deploy' | 'key_rotation' | 'policy'
        self.component = component
        self.description = description
        self.changed_by = changed_by
        self.before = before
        self.after = after
        self.ticket_id = ticket_id
        self.timestamp = datetime.now().isoformat()
        self.hostname = socket.gethostname()

    def to_dict(self) -> dict:
        return {
            'change_type': self.change_type,
            'component': self.component,
            'description': self.description,
            'changed_by': self.changed_by,
            'before': self.before,
            'after': self.after,
            'ticket_id': self.ticket_id,
            'timestamp': self.timestamp,
            'hostname': self.hostname,
        }


class ChangeManager:
    """
    Implements GLBA §314.4(c)(7): Change Management Procedures.

    Records every notable system change (config updates, deployments, key
    rotations, policy changes) to both a local JSON log and an optional
    Merkle-chained GLBAAuditor for tamper-evident storage.

    Args:
        auditor: Optional GLBAAuditor. When provided changes are written to
                 the cryptographic audit trail.
        log_dir: Directory for the local change log JSON file.
    """

    LOG_FILENAME = 'change_log.json'

    def __init__(self, auditor=None, log_dir: Optional[Path] = None):
        self._auditor = auditor
        default_dir = Path(
            os.environ.get('COMPLYCHAIN_CHANGE_LOG_DIR', '')
        ) or Path.home() / '.complychain' / 'changes'
        self._log_dir = Path(log_dir) if log_dir else default_dir
        self._log_file = self._log_dir / self.LOG_FILENAME
        self._records: List[dict] = []
        self._load()

    # ------------------------------------------------------------------
    # Recording changes
    # ------------------------------------------------------------------

    def record(
        self,
        change_type: str,
        component: str,
        description: str,
        changed_by: str,
        before: Optional[Any] = None,
        after: Optional[Any] = None,
        ticket_id: Optional[str] = None,
    ) -> str:
        """
        Record a change event.

        Returns a change ID (ISO timestamp + component slug).
        """
        record = ChangeRecord(
            change_type=change_type,
            component=component,
            description=description,
            changed_by=changed_by,
            before=before,
            after=after,
            ticket_id=ticket_id,
        )
        change_id = f"{record.timestamp}_{component}"
        entry = {'change_id': change_id, **record.to_dict()}
        self._records.append(entry)
        self._save()
        self._audit(entry)
        logger.info(f"Change recorded [{change_type}] {component}: {description} (by {changed_by})")
        return change_id

    def record_config_change(
        self,
        key: str,
        before: Any,
        after: Any,
        changed_by: str,
        ticket_id: Optional[str] = None,
    ) -> str:
        """Convenience wrapper for configuration changes."""
        return self.record(
            change_type='config',
            component=key,
            description=f"Config key '{key}' changed",
            changed_by=changed_by,
            before=before,
            after=after,
            ticket_id=ticket_id,
        )

    def record_key_rotation(self, algorithm: str, changed_by: str, ticket_id: Optional[str] = None) -> str:
        """Convenience wrapper for cryptographic key rotation events."""
        return self.record(
            change_type='key_rotation',
            component=f"crypto:{algorithm}",
            description=f"{algorithm} key rotated",
            changed_by=changed_by,
            ticket_id=ticket_id,
        )

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def get_recent(self, limit: int = 50) -> List[dict]:
        """Return the most recent *limit* change records."""
        return self._records[-limit:]

    def get_by_component(self, component: str) -> List[dict]:
        """Return all changes for a specific component."""
        return [r for r in self._records if r.get('component') == component]

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self) -> None:
        if not self._log_file.exists():
            return
        try:
            self._records = json.loads(self._log_file.read_text())
        except Exception as e:
            logger.warning(f"Could not load change log: {e}")
            self._records = []

    def _save(self) -> None:
        self._log_dir.mkdir(parents=True, exist_ok=True)
        self._log_file.write_text(json.dumps(self._records, indent=2))
        os.chmod(self._log_file, 0o600)

    def _audit(self, entry: dict) -> None:
        if self._auditor is None:
            return
        try:
            self._auditor.log_transaction(
                tx_data=entry,
                signature=b'change_management_event',
            )
        except Exception as e:
            logger.warning(f"Could not log change event to audit chain: {e}")
