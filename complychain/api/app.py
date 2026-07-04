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

try:
    from fastapi import FastAPI
    from .auth import APIKeyMiddleware
    from .routes.health import router as health_router
    from .routes.scan import router as scan_router
    from .routes.regulations import router as regulations_router
    from .routes.audit import router as audit_router

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

        app.add_middleware(APIKeyMiddleware)

        app.include_router(health_router)
        app.include_router(scan_router)
        app.include_router(regulations_router)
        app.include_router(audit_router)

        return app

except ImportError as _exc:
    def create_app():  # type: ignore[misc]
        raise ImportError(
            "FastAPI is required to use the ComplyChain REST API. "
            "Install with: pip install 'complychain[api]'"
        ) from _exc
