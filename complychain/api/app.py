"""
ComplyChain FastAPI application factory.

Install the API extras first:
    pip install 'complychain[api]'

Usage:
    from complychain.api import create_app
    app = create_app()

    # Or use the CLI:
    complychain serve --port 8080
"""

import os

try:
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from .auth import APIKeyMiddleware
    from .routes.health import router as health_router
    from .routes.scan import router as scan_router
    from .routes.regulations import router as regulations_router
    from .routes.audit import router as audit_router
    from .routes.sign import router as sign_router
    from .routes.keys import keys_router, key_rotation_router
    from .routes.sar import router as sar_router
    from .routes.monitor import router as monitor_router

    def create_app() -> FastAPI:
        app = FastAPI(
            title="ComplyChain API",
            description=(
                "REST interface for ComplyChain compliance toolkit. "
                "Covers GLBA, PCI-DSS, DORA, SOC 2, HIPAA."
            ),
            version="3.0.0",
            docs_url="/docs",
            redoc_url="/redoc",
        )

        # Starlette wraps middleware in the reverse order added, so the
        # last one added ends up outermost and runs first per request.
        # CORSMiddleware must be added last so it intercepts preflight
        # OPTIONS requests before APIKeyMiddleware can reject them.
        app.add_middleware(APIKeyMiddleware)

        allowed_origins = [
            origin.strip()
            for origin in os.environ.get(
                "CORS_ALLOWED_ORIGINS", "https://complychain.dev"
            ).split(",")
            if origin.strip()
        ]
        app.add_middleware(
            CORSMiddleware,
            allow_origins=allowed_origins,
            allow_methods=["GET", "POST", "DELETE"],
            allow_headers=["X-ComplyChain-API-Key", "Content-Type"],
        )

        app.include_router(health_router)
        app.include_router(scan_router)
        app.include_router(regulations_router)
        app.include_router(audit_router)
        app.include_router(sign_router)
        app.include_router(keys_router)
        app.include_router(key_rotation_router)
        app.include_router(sar_router)
        app.include_router(monitor_router)

        return app

except ImportError as _exc:
    def create_app():  # type: ignore[misc]
        raise ImportError(
            "FastAPI is required to use the ComplyChain REST API. "
            "Install with: pip install 'complychain[api]'"
        ) from _exc
