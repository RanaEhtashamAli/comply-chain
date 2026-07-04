"""Pydantic v2 request/response schemas for the ComplyChain REST API."""

try:
    from pydantic import BaseModel, Field
    from typing import Any, Dict, List, Optional

    class ScanRequest(BaseModel):
        tx_data: Dict[str, Any]
        explain: bool = False
        rule_engine_path: Optional[str] = None

    class AssessRequest(BaseModel):
        name: str
        jurisdiction: str = "US"
        entity_type: str = "fintech"
        processes_card_payments: bool = False
        eu_nexus: bool = False
        employee_count: int = 0
        hipaa_covered_entity: bool = False

    class HealthResponse(BaseModel):
        status: str
        version: str

except ImportError:
    pass
