"""API key middleware for ComplyChain REST API."""

import os
from typing import Callable

try:
    from fastapi import Request, HTTPException
    from fastapi.responses import JSONResponse
    from starlette.middleware.base import BaseHTTPMiddleware

    _API_KEY_HEADER = "X-ComplyChain-API-Key"

    class APIKeyMiddleware(BaseHTTPMiddleware):
        """Enforces X-ComplyChain-API-Key header when COMPLYCHAIN_API_KEY env var is set."""

        async def dispatch(self, request: Request, call_next: Callable):
            required_key = os.environ.get("COMPLYCHAIN_API_KEY")
            if required_key:
                provided = request.headers.get(_API_KEY_HEADER)
                if provided != required_key:
                    return JSONResponse(
                        status_code=401,
                        content={"detail": f"Missing or invalid {_API_KEY_HEADER} header."},
                    )
            return await call_next(request)

except ImportError:
    pass
