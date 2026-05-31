# backend/redis_client.py
# Optional Redis connection helper.
#
# Redis is a *cache / pub-sub* layer here — never a hard dependency. If it is
# unreachable, get_redis() returns None and every caller falls back to the
# in-process behaviour (token-bucket rate limiting, in-memory event bus). The
# first failed connection flips a sticky flag so we never pay a connection
# timeout on the hot path for the rest of the process lifetime.

from __future__ import annotations

import logging
import os

try:
    import redis.asyncio as aioredis
except ImportError:  # redis client not installed — stay in in-process mode
    aioredis = None  # type: ignore[assignment]

_log = logging.getLogger(__name__)

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

_client: "aioredis.Redis | None" = None
_unavailable = False


async def get_redis():
    """
    Return a connected Redis client, or None if Redis is unavailable.

    The first connection is verified with PING; if it fails we log once and
    return None forever after (until close_redis() resets the state), so the
    app keeps working without Redis.
    """
    global _client, _unavailable
    if aioredis is None or _unavailable:
        return None
    if _client is None:
        try:
            _client = aioredis.from_url(
                REDIS_URL,
                decode_responses=True,
                socket_connect_timeout=2,
                socket_timeout=2,
            )
            await _client.ping()
            _log.info("Redis connected at %s", REDIS_URL)
        except Exception as exc:  # connection refused, timeout, auth, …
            _log.warning(
                "Redis unavailable (%s) — falling back to in-process behaviour", exc
            )
            _client = None
            _unavailable = True
            return None
    return _client


async def close_redis() -> None:
    """Close the Redis connection (registered on app shutdown)."""
    global _client, _unavailable
    if _client is not None:
        try:
            await _client.aclose()
        except Exception:  # pragma: no cover - best effort
            pass
        _client = None
    _unavailable = False


# ── Best-effort cache helpers ──────────────────────────────────────────────
# Every helper is a no-op (or returns None) when Redis is unavailable, so
# callers never need their own try/except for the "Redis down" case.


async def cache_get(key: str) -> "str | None":
    """Return the cached string for ``key``, or None (also None if Redis down)."""
    r = await get_redis()
    if r is None:
        return None
    try:
        return await r.get(key)
    except Exception as exc:  # pragma: no cover - best effort
        _log.warning("Redis GET %s failed: %s", key, exc)
        return None


async def cache_set(key: str, value: str, ttl: int) -> None:
    """Set ``key`` to ``value`` with a TTL (seconds). No-op if Redis is down."""
    r = await get_redis()
    if r is None:
        return
    try:
        await r.setex(key, ttl, value)
    except Exception as exc:  # pragma: no cover - best effort
        _log.warning("Redis SETEX %s failed: %s", key, exc)


async def cache_delete(*keys: str) -> None:
    """Delete one or more keys. No-op if Redis is down."""
    if not keys:
        return
    r = await get_redis()
    if r is None:
        return
    try:
        await r.delete(*keys)
    except Exception as exc:  # pragma: no cover - best effort
        _log.warning("Redis DEL %s failed: %s", keys, exc)
