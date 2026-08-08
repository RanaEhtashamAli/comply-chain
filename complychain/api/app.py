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

import logging
import os

logger = logging.getLogger(__name__)

try:
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
    from starlette.middleware.base import BaseHTTPMiddleware
    from .auth import APIKeyMiddleware
    from .routes.health import router as health_router
    from .routes.scan import router as scan_router
    from .routes.regulations import router as regulations_router
    from .routes.audit import router as audit_router
    from .routes.sign import router as sign_router
    from .routes.keys import keys_router, key_rotation_router
    from .routes.sar import router as sar_router
    from .routes.monitor import router as monitor_router
    from .routes.admin import router as admin_router

    class ExceptionToJSONMiddleware(BaseHTTPMiddleware):
        """
        Turn unhandled exceptions into a JSON 500 from *inside* the CORS layer.

        Starlette's built-in ServerErrorMiddleware sits outside CORSMiddleware,
        so an unhandled exception returned a bare 500 carrying no
        Access-Control-Allow-Origin header. The browser then surfaced it as a
        CORS policy failure rather than a server error, which points debugging
        at the wrong subsystem entirely. Handling it here keeps the response
        inside CORS so the real status reaches the client.
        """

        async def dispatch(self, request, call_next):
            try:
                return await call_next(request)
            except Exception:
                logger.exception(
                    "Unhandled error serving %s %s", request.method, request.url.path
                )
                return JSONResponse(
                    status_code=500,
                    content={"detail": "Internal server error."},
                )

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
        # Added after APIKeyMiddleware and before CORSMiddleware, so it wraps
        # the auth layer and the routes while itself staying inside CORS.
        app.add_middleware(ExceptionToJSONMiddleware)

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
        app.include_router(admin_router)

        return app

except ImportError as _exc:
    def create_app():  # type: ignore[misc]
        raise ImportError(
            "FastAPI is required to use the ComplyChain REST API. "
            "Install with: pip install 'complychain[api]'"
        ) from _exc
