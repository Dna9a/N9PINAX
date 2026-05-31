# backend/__init__.py
# FastAPI backend exposing the scanner over HTTP + SSE.

from .app import create_app

__all__ = ["create_app"]
