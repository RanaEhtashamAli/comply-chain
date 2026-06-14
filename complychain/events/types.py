"""Event types and the Event dataclass for the ComplyChain event system."""

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict


class EventType(str, Enum):
    THREAT_DETECTED           = "threat_detected"
    SANCTION_HIT              = "sanction_hit"
    COMPLIANCE_STATUS_CHANGED = "compliance_status_changed"
    ASSESSMENT_COMPLETED      = "assessment_completed"
    DRIFT_DETECTED            = "drift_detected"


@dataclass
class Event:
    event_type: EventType
    payload: Dict[str, Any]
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp,
            "payload": self.payload,
        }
