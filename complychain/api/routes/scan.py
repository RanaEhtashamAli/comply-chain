"""Transaction scan endpoints."""

import logging

logger = logging.getLogger(__name__)

try:
    from fastapi import APIRouter, HTTPException
    from ..schemas import ScanRequest

    router = APIRouter(prefix="/scan", tags=["scan"])

    def _audit_scan(tx_data: dict, result: dict) -> None:
        """
        Append the scan to the Merkle-chained audit log (§314.4(c)(8)).

        Scanning was previously not recorded anywhere — log_transaction() was
        only ever called by the data-disposal, vendor-management and
        change-management modules — so the Audit page's chain stayed empty no
        matter how much traffic was scanned.

        Only a summary is written, plus a SHA-256 over the canonical full
        transaction. That preserves tamper-evidence over the exact input that
        was scanned without copying raw account identifiers into a plaintext
        chain file, which would work against the rule this log exists to
        satisfy.

        Best-effort: an audit-logging failure must never fail the caller's scan.
        """
        try:
            import hashlib
            import json

            from ...audit_system import GLBAAuditor

            GLBAAuditor().log_transaction(
                tx_data={
                    "event": "transaction_scan",
                    "amount": tx_data.get("amount"),
                    "currency": tx_data.get("currency"),
                    "risk_score": result.get("risk_score"),
                    "threat_flags": result.get("threat_flags", []),
                    "tx_sha256": hashlib.sha256(
                        json.dumps(tx_data, sort_keys=True, default=str).encode()
                    ).hexdigest(),
                },
                signature=b"scan_event",
            )
        except Exception as exc:
            logger.warning("Could not log scan to audit chain: %s", exc)

    @router.post("")
    def scan(req: ScanRequest):
        from ...threat_scanner import GLBAScanner

        result = GLBAScanner().scan(req.tx_data)
        _audit_scan(req.tx_data, result)
        return result

    @router.post("/explain")
    def scan_explain(req: ScanRequest):
        from ...threat_scanner import GLBAScanner
        from ...reporting import ExplanationEngine

        result = GLBAScanner().scan(req.tx_data)
        _audit_scan(req.tx_data, result)
        explanation = ExplanationEngine().explain(result, req.tx_data)
        return {**result, "explanation": explanation.to_dict()}

except ImportError:
    pass
