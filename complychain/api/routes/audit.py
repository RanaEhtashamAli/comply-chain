"""Audit chain status endpoints."""

try:
    from fastapi import APIRouter

    router = APIRouter(prefix="/audit", tags=["audit"])

    @router.get("/status")
    def audit_status():
        from ...verification import AuditChainVerifier
        result = AuditChainVerifier().verify()
        return result.to_dict()

    @router.get("/chain")
    def audit_chain():
        import json
        import os
        from pathlib import Path
        audit_dir = Path(os.environ.get(
            "COMPLYCHAIN_AUDIT_DIR", str(Path.home() / ".complychain" / "audit")
        ))
        chain_file = audit_dir / "audit_chain.json"
        if not chain_file.exists():
            return {"entries": []}
        try:
            return json.loads(chain_file.read_text())
        except Exception:
            return {"entries": [], "error": "Could not parse audit_chain.json"}

except ImportError:
    pass
