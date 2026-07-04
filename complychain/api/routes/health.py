"""Health check endpoints."""

try:
    from fastapi import APIRouter
    from ..schemas import HealthResponse

    router = APIRouter(tags=["health"])

    @router.get("/health", response_model=HealthResponse)
    def health():
        return {"status": "ok", "version": "3.0.0"}

    @router.get("/health/detailed")
    def health_detailed():
        from ...verification import KeyVerifier, AuditChainVerifier, MFAVerifier
        return {
            "status": "ok",
            "version": "3.0.0",
            "key_verification": KeyVerifier().verify().to_dict(),
            "audit_chain": AuditChainVerifier().verify().to_dict(),
            "mfa": MFAVerifier().verify().to_dict(),
        }

except ImportError:
    pass
