"""Suspicious Activity Report (SAR) generation endpoint."""

try:
    from fastapi import APIRouter, HTTPException
    from fastapi.responses import Response
    from pydantic import BaseModel
    from typing import Any, Dict

    router = APIRouter(tags=["sar"])

    class GenerateSarRequest(BaseModel):
        scan_result: Dict[str, Any]
        tx_data: Dict[str, Any]
        filing_type: str = "INITIAL"
        format: str = "pdf"

    _MEDIA_TYPES = {
        "pdf": "application/pdf",
        "xml": "application/xml",
        "json": "application/json",
    }

    @router.post("/generate-sar")
    def generate_sar(req: GenerateSarRequest):
        fmt = req.format.lower()
        if fmt not in _MEDIA_TYPES:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported format '{req.format}' — use pdf, xml, or json.",
            )

        from ...reporting import SARGenerator
        try:
            sar = SARGenerator().generate(req.scan_result, req.tx_data, req.filing_type)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"SAR generation failed: {exc}")

        if fmt == "pdf":
            content = sar.to_pdf()
        elif fmt == "xml":
            content = sar.to_xml().encode("utf-8")
        else:
            import json
            content = json.dumps(sar.to_dict(), indent=2, default=str).encode("utf-8")

        return Response(
            content=content,
            media_type=_MEDIA_TYPES[fmt],
            headers={"Content-Disposition": f'attachment; filename="sar_{sar.sar_id}.{fmt}"'},
        )

except ImportError:
    pass
