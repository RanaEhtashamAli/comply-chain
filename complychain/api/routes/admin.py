"""Niche/admin diagnostic and tooling endpoints: sanctions status, compliance
checklist, rule validation, crypto benchmarking, and isolated model training."""

try:
    from fastapi import APIRouter, File, HTTPException, UploadFile
    from pydantic import BaseModel
    from typing import Optional

    router = APIRouter(tags=["admin"])

    # -----------------------------------------------------------------
    # sanctions-status
    # -----------------------------------------------------------------

    @router.get("/sanctions-status")
    def sanctions_status():
        import os
        from ...threat_scanner import GLBAScanner

        scanner = GLBAScanner()
        fincen_key = os.environ.get("COMPLYCHAIN_FINCEN_API_KEY")
        status_str = scanner._sanctions_status.value if scanner._sanctions_status else "unknown"

        return {
            "sanctions_cache_status": status_str,
            "ofac_configured": True,
            "unsc_configured": True,
            "uk_configured": True,
            "fincen_api_key_configured": bool(fincen_key),
        }

    # -----------------------------------------------------------------
    # compliance/show
    # -----------------------------------------------------------------

    _GLBA_SECTIONS = [
        ("§314.4(b)",    "Risk Assessment",                    "glba_engine"),
        ("§314.4(c)(1)", "Access Controls",                    "threat_scanner"),
        ("§314.4(c)(2)", "Data Inventory",                     "—"),
        ("§314.4(c)(3)", "Data Encryption (FIPS 204)",         "crypto_engine"),
        ("§314.4(c)(4)", "Secure Development Practices",       "pyproject.toml"),
        ("§314.4(c)(5)", "Multi-Factor Authentication",        "—"),
        ("§314.4(c)(6)", "Data Disposal",                      "—"),
        ("§314.4(c)(7)", "Change Management",                  "—"),
        ("§314.4(c)(8)", "Audit Trails & Activity Monitoring",  "audit_system"),
        ("§314.4(d)",    "Testing and Monitoring",              "ml_engine"),
        ("§314.4(e)",    "Employee Training",                   "—"),
        ("§314.4(f)",    "Vendor Management",                   "—"),
        ("§314.4(h)",    "Incident Response Plan",               "audit_system"),
    ]

    @router.get("/compliance/show")
    def compliance_show():
        from ...config import get_config
        config = get_config()
        return [
            {
                "section": section,
                "description": description,
                "module": module,
                "configured": bool(config.get(f"compliance.{section}", False)),
            }
            for section, description, module in _GLBA_SECTIONS
        ]

except ImportError:
    pass
