# backend/rate_limit.py
# Per-IP rate limiter for FastAPI dependencies.
#
# Primary path: a Redis sliding-window counter (shared across uvicorn workers).
# Fallback path: an in-process token bucket — used when Redis is unavailable,
# so a single-worker deployment (or a dev box without Redis) still works. The
# fallback is per-process, so it does NOT protect against limit bypass when
# horizontally scaled — Redis is what makes the limit cluster-wide.

from __future__ import annotations

import logging
import os
import time
from collections import defaultdict, deque
from threading import Lock

from fastapi import HTTPException, Request, status

from scanner.config import get_config

from .redis_client import get_redis

_log = logging.getLogger(__name__)


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


class TokenBucket:
    def __init__(self, max_per_minute: int) -> None:
        self.max_per_minute = max_per_minute
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            window = self._hits[key]
            cutoff = now - 60.0
            while window and window[0] < cutoff:
                window.popleft()
            if len(window) >= self.max_per_minute:
                return False
            window.append(now)
            return True


_BUCKET: TokenBucket | None = None


def _bucket() -> TokenBucket:
    global _BUCKET
    if _BUCKET is None:
        _BUCKET = TokenBucket(get_config().api_rate_limit_per_minute)
    return _BUCKET


def _client_ip(request: Request) -> str:
    """Resolve the client IP used as the rate-limit key.

    Behind a reverse proxy every request appears to come from the proxy's IP,
    so one shared IP would exhaust the limit for everyone (audit F-074). When
    ``SCANNER_TRUST_PROXY`` is enabled we use the left-most ``X-Forwarded-For``
    entry (the original client). It's OFF by default because a client can forge
    that header when NOT behind a trusted proxy — enable it only when a proxy
    you control always sets/overwrites XFF.
    """
    if _env_bool("SCANNER_TRUST_PROXY", False):
        xff = request.headers.get("x-forwarded-for", "")
        first = xff.split(",")[0].strip()
        if first:
            return first
    return request.client.host if request.client else "anonymous"


def _too_many() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Rate limit exceeded",
        headers={"Retry-After": "60"},
    )


async def enforce_rate_limit(request: Request) -> None:
    """FastAPI dependency — raises 429 when the per-IP budget is exhausted."""
    client_ip = _client_ip(request)
    limit = get_config().api_rate_limit_per_minute

    redis = await get_redis()
    if redis is not None:
        try:
            key = f"rl:{client_ip}"
            count = await redis.incr(key)
            if count == 1:
                await redis.expire(key, 60)
            if count > limit:
                raise _too_many()
            return
        except HTTPException:
            raise
        except Exception as exc:  # Redis hiccup — degrade to in-process bucket
            _log.warning("Redis rate-limit failed (%s) — using in-process bucket", exc)

    if not _bucket().allow(client_ip):
        raise _too_many()
