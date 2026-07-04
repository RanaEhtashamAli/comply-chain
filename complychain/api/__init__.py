"""complychain.api — FastAPI REST interface (optional: pip install complychain[api])."""

try:
    from .app import create_app
    __all__ = ["create_app"]
except ImportError:
    __all__ = []
