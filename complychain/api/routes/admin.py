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

    # -----------------------------------------------------------------
    # rules/validate
    # -----------------------------------------------------------------

    class ValidateRulesRequest(BaseModel):
        yaml_content: str

    @router.post("/rules/validate")
    def validate_rules(req: ValidateRulesRequest):
        import tempfile
        from pathlib import Path
        from ...rules import RuleEngine

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(req.yaml_content)
            tmp_path = Path(f.name)
        try:
            try:
                engine = RuleEngine.load(tmp_path)
            except Exception as exc:
                raise HTTPException(status_code=400, detail=f"Could not parse YAML: {exc}")
            errors = engine.validate()
            return {"valid": not errors, "rule_count": len(engine._rules), "errors": errors}
        finally:
            tmp_path.unlink(missing_ok=True)

    # -----------------------------------------------------------------
    # benchmark
    # -----------------------------------------------------------------

    class BenchmarkRequest(BaseModel):
        samples: int = 100
        algorithm: str = "dilithium3"

    _MAX_BENCHMARK_SAMPLES = 500

    @router.post("/benchmark")
    def run_benchmark(req: BenchmarkRequest):
        import time
        from ...crypto_engine import QuantumSafeSigner

        samples = min(max(req.samples, 1), _MAX_BENCHMARK_SAMPLES)
        signer = QuantumSafeSigner(algorithm=req.algorithm.upper())
        test_data = b"benchmark_test_data" * 1000

        key_gen_times = []
        for _ in range(min(samples, 10)):
            start = time.time()
            signer.generate_keys()
            key_gen_times.append(time.time() - start)

        sign_times = []
        for _ in range(samples):
            start = time.time()
            signer.sign(test_data)
            sign_times.append(time.time() - start)

        return {
            "key_generation": {
                "avg_ms": (sum(key_gen_times) / len(key_gen_times)) * 1000,
                "samples": len(key_gen_times),
            },
            "signing": {
                "avg_ms": (sum(sign_times) / len(sign_times)) * 1000,
                "samples": len(sign_times),
            },
        }

except ImportError:
    pass
