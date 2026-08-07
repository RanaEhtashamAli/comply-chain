"""Audit chain status, compliance report, and evidence export endpoints."""

try:
    from fastapi import APIRouter, HTTPException
    from fastapi.responses import Response
    from pydantic import BaseModel
    from typing import List, Optional

    router = APIRouter(prefix="/audit", tags=["audit"])

    class EvidenceRequest(BaseModel):
        regulations: Optional[List[str]] = None
        sign: bool = True

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

    @router.get("/report")
    def audit_report(report_type: str):
        from ...audit_system import GLBAAuditor
        try:
            pdf_bytes = GLBAAuditor().generate_report(report_type)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Report generation failed: {exc}")
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="glba_{report_type}_report.pdf"'},
        )

    @router.post("/evidence")
    def audit_evidence(req: EvidenceRequest):
        import tempfile
        from pathlib import Path
        from ...export.evidence import EvidencePackage
        try:
            with tempfile.TemporaryDirectory() as tmp_dir:
                output_path = Path(tmp_dir) / "evidence.zip"
                result_path = EvidencePackage().build(
                    regulations=req.regulations, output_path=output_path, sign=req.sign
                )
                content = result_path.read_bytes()
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Evidence export failed: {exc}")
        return Response(
            content=content,
            media_type="application/zip",
            headers={"Content-Disposition": 'attachment; filename="complychain_evidence.zip"'},
        )

except ImportError:
    pass
