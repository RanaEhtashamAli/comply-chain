"""complychain.regulations — Pluggable multi-regulation compliance framework."""

from .base import (
    BaseRegulation,
    ComplianceStatus,
    ControlResult,
    InstitutionProfile,
    RegulationReport,
)
from .registry import RegulationRegistry, default_registry
from .glba import GLBARegulation
from .pci_dss import PCIDSSRegulation
from .dora import DORARegulation
from .soc2 import SOC2Regulation

__all__ = [
    "BaseRegulation",
    "ComplianceStatus",
    "ControlResult",
    "InstitutionProfile",
    "RegulationReport",
    "RegulationRegistry",
    "default_registry",
    "GLBARegulation",
    "PCIDSSRegulation",
    "DORARegulation",
    "SOC2Regulation",
]
