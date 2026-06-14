"""
RegulationRegistry — thread-safe registry of compliance regulation instances.
"""

import threading
from typing import Dict, List, Optional

from .base import BaseRegulation, InstitutionProfile, RegulationReport


class RegulationRegistry:
    """Thread-safe registry of available compliance regulations.

    A default, pre-populated singleton is available as `default_registry`.
    For test isolation, construct a fresh `RegulationRegistry()` directly.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._regulations: Dict[str, BaseRegulation] = {}

    def register(self, regulation: BaseRegulation) -> None:
        """Register a regulation instance. Raises ValueError on duplicate ID."""
        with self._lock:
            rid = regulation.regulation_id
            if rid in self._regulations:
                raise ValueError(f"Regulation already registered: '{rid}'")
            self._regulations[rid] = regulation

    def get(self, regulation_id: str) -> Optional[BaseRegulation]:
        with self._lock:
            return self._regulations.get(regulation_id)

    def list_all(self) -> List[BaseRegulation]:
        with self._lock:
            return list(self._regulations.values())

    def list_applicable(self, profile: InstitutionProfile) -> List[BaseRegulation]:
        with self._lock:
            return [r for r in self._regulations.values() if r.is_applicable(profile)]

    def unregister(self, regulation_id: str) -> bool:
        with self._lock:
            return self._regulations.pop(regulation_id, None) is not None

    def assess(
        self,
        regulation_id: str,
        profile: InstitutionProfile,
    ) -> Optional[RegulationReport]:
        reg = self.get(regulation_id)
        return reg.assess(profile) if reg is not None else None

    def assess_all(self, profile: InstitutionProfile) -> Dict[str, RegulationReport]:
        with self._lock:
            items = list(self._regulations.items())
        return {rid: reg.assess(profile) for rid, reg in items}


def _build_default_registry() -> RegulationRegistry:
    """Import and register all 4 built-in regulations.
    Deferred imports inside the function body break any circular-import risk.
    """
    from .glba import GLBARegulation
    from .pci_dss import PCIDSSRegulation
    from .dora import DORARegulation
    from .soc2 import SOC2Regulation

    registry = RegulationRegistry()
    registry.register(GLBARegulation())
    registry.register(PCIDSSRegulation())
    registry.register(DORARegulation())
    registry.register(SOC2Regulation())
    return registry


default_registry: RegulationRegistry = _build_default_registry()
