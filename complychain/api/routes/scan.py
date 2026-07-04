"""Transaction scan endpoints."""

try:
    from fastapi import APIRouter, HTTPException
    from ..schemas import ScanRequest

    router = APIRouter(prefix="/scan", tags=["scan"])

    @router.post("")
    def scan(req: ScanRequest):
        from ...threat_scanner import GLBAScanner
        return GLBAScanner().scan(req.tx_data)

    @router.post("/explain")
    def scan_explain(req: ScanRequest):
        from ...threat_scanner import GLBAScanner
        from ...reporting import ExplanationEngine
        result = GLBAScanner().scan(req.tx_data)
        explanation = ExplanationEngine().explain(result, req.tx_data)
        return {**result, "explanation": explanation.to_dict()}

except ImportError:
    pass
