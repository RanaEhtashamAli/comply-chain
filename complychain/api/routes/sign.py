"""File signing and signature verification endpoints."""

try:
    from fastapi import APIRouter, File, Form, HTTPException, UploadFile
    from fastapi.responses import Response
    from typing import Optional

    router = APIRouter(tags=["sign"])

    def _key_dir():
        import os
        from pathlib import Path
        from ...crypto_engine import DEFAULT_KEY_DIR
        return Path(os.environ.get("COMPLYCHAIN_KEY_DIR", str(DEFAULT_KEY_DIR)))

    def _resolve_signing_key(algorithm: str):
        """Load the institutional key for `algorithm`, generating it if it doesn't exist yet."""
        from ...crypto_engine import QuantumSafeSigner
        signer = QuantumSafeSigner(algorithm=algorithm.upper())
        key_dir = _key_dir()
        algo_slug = signer.algorithm.lower().replace('-', '_').replace('+', 'plus')
        priv_path = key_dir / f"private_key_{algo_slug}.pem"
        pub_path = key_dir / f"public_key_{algo_slug}.pem"

        if priv_path.exists() and pub_path.exists():
            signer.import_private_key_pem(priv_path.read_text())
            signer.import_public_key_pem(pub_path.read_text())
        else:
            signer.generate_keys()
            key_dir.mkdir(parents=True, exist_ok=True)
            priv_path.write_text(signer.export_private_key_pem())
            pub_path.write_text(signer.export_public_key_pem())
            priv_path.chmod(0o600)

        return signer

    def _default_public_key() -> Optional[bytes]:
        key_dir = _key_dir()
        if not key_dir.exists():
            return None
        pub_path = next(key_dir.glob("public_key_*.pem"), None)
        return pub_path.read_bytes() if pub_path else None

    def _signer_for_public_key_pem(pem_bytes: bytes):
        from ...crypto_engine import QuantumSafeSigner
        text = pem_bytes.decode("utf-8", errors="ignore").strip()
        first_line = text.splitlines()[0] if text else ""
        if first_line == "-----BEGIN PUBLIC KEY-----":
            return QuantumSafeSigner(algorithm="RSA-4096")
        if first_line.startswith("-----BEGIN ") and first_line.endswith(" PUBLIC KEY-----"):
            algo = first_line[len("-----BEGIN "):-len(" PUBLIC KEY-----")]
            return QuantumSafeSigner(algorithm=algo)
        raise ValueError("Unrecognized public key PEM format")

    @router.post("/sign")
    async def sign_file(
        file: UploadFile = File(...),
        algorithm: str = Form("dilithium3"),
    ):
        data = await file.read()
        try:
            signer = _resolve_signing_key(algorithm)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Could not resolve signing key: {exc}")
        try:
            signature = signer.sign(data)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Signing failed: {exc}")
        return Response(
            content=signature,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{file.filename}.sig"'},
        )

    @router.post("/verify")
    async def verify_file(
        file: UploadFile = File(...),
        signature: UploadFile = File(...),
        public_key: UploadFile = File(None),
    ):
        data = await file.read()
        sig_data = await signature.read()

        if public_key is not None:
            pub_key_bytes = await public_key.read()
        else:
            pub_key_bytes = _default_public_key()
            if pub_key_bytes is None:
                raise HTTPException(
                    status_code=404,
                    detail="No institutional public key found — sign something first or supply public_key.",
                )

        try:
            signer = _signer_for_public_key_pem(pub_key_bytes)
            is_valid = signer.verify(data, sig_data, pub_key_bytes)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Verification failed: {exc}")

        return {"valid": is_valid, "algorithm": signer.algorithm}

except ImportError:
    pass
