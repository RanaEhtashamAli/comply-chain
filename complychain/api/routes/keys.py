"""Institutional signing key management and rotation endpoints."""

try:
    from fastapi import APIRouter, HTTPException
    from fastapi.responses import Response
    from pydantic import BaseModel
    from typing import Optional

    keys_router = APIRouter(prefix="/keys", tags=["keys"])
    key_rotation_router = APIRouter(prefix="/key-rotation", tags=["key-rotation"])

    class ImportKeyRequest(BaseModel):
        private_key_pem: str
        public_key_pem: str

    def _key_dir():
        import os
        from pathlib import Path
        from ...crypto_engine import DEFAULT_KEY_DIR
        return Path(os.environ.get("COMPLYCHAIN_KEY_DIR", str(DEFAULT_KEY_DIR)))

    def _current_public_key_pem() -> Optional[str]:
        key_dir = _key_dir()
        if not key_dir.exists():
            return None
        pub_path = next(key_dir.glob("public_key_*.pem"), None)
        return pub_path.read_text() if pub_path else None

    @keys_router.get("/public")
    def get_public_key():
        pem = _current_public_key_pem()
        if pem is None:
            raise HTTPException(status_code=404, detail="No institutional key found — sign something first or generate one.")
        return Response(content=pem, media_type="application/x-pem-file")

    @keys_router.post("/generate")
    def generate_key(algorithm: Optional[str] = None):
        from ...key_management import KeyRotationManager
        result = KeyRotationManager().generate(algorithm=algorithm)
        if not result.ok:
            raise HTTPException(status_code=500, detail="; ".join(result.findings) or "Key generation failed.")
        return {
            "ok": True,
            "algorithm": result.rotation_manifest.get("new_algorithm"),
            "public_key": _current_public_key_pem(),
        }

    @keys_router.post("/import")
    def import_key(req: ImportKeyRequest):
        from ...key_management import KeyRotationManager
        result = KeyRotationManager().import_key(req.private_key_pem, req.public_key_pem)
        if not result.ok:
            raise HTTPException(status_code=400, detail="; ".join(result.findings) or "Key import failed.")
        return {
            "ok": True,
            "algorithm": result.rotation_manifest.get("new_algorithm"),
            "public_key": _current_public_key_pem(),
        }

    @key_rotation_router.get("/check")
    def check_rotation():
        from ...verification import KeyVerifier
        return KeyVerifier().verify().to_dict()

    @key_rotation_router.post("/rotate")
    def rotate_key():
        from ...key_management import KeyRotationManager
        result = KeyRotationManager().rotate()
        return {
            "ok": result.ok,
            "old_key_archived": str(result.old_key_archived) if result.old_key_archived else None,
            "new_key_dir": str(result.new_key_dir),
            "rotation_manifest": result.rotation_manifest,
            "findings": result.findings,
        }

    @key_rotation_router.get("/history")
    def rotation_history():
        from ...key_management import KeyRotationManager
        return KeyRotationManager().rotation_history()

except ImportError:
    pass
