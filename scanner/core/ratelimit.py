# scanner/core/ratelimit.py
# Shared, cross-protocol outbound rate limiter.
#
# Previously each probe module (icmp_scan / syn_scan / udp_scan) kept its own
# copy of a rate limiter that rebuilt an O(n) timestamp list under a lock on
# every single packet, and — worse — maintained an INDEPENDENT budget. Three
# independent limiters each capped at `rate_limit_pps` meant the real combined
# egress could reach 3× the configured budget, defeating the "don't look like
# an IDS-tripping flood" goal (audit F-036 / F-037 / F-058).
#
# This module provides ONE process-wide limiter shared by every probe type.
# It reserves the next send slot atomically (O(1)) and sleeps outside the lock,
# so N concurrent threads are smoothly spaced at exactly `1 / pps` seconds
# apart regardless of which protocol they belong to.

from __future__ import annotations

import threading
import time

from ..config import get_config


class SlotRateLimiter:
    """Global token-free rate limiter using monotonic slot reservation.

    Each caller atomically claims the next available send time (spaced
    ``1 / pps`` apart) and then sleeps until that time *outside* the lock. This
    is O(1) per acquire and enforces a single shared budget across all probe
    protocols. After an idle period the next slot is simply "now", so callers
    are never penalised for a quiet gap.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._next_slot = 0.0

    def acquire(self) -> None:
        pps = max(1, get_config().rate_limit_pps)
        interval = 1.0 / pps
        with self._lock:
            now = time.monotonic()
            slot = self._next_slot if self._next_slot > now else now
            self._next_slot = slot + interval
        wait = slot - time.monotonic()
        if wait > 0:
            time.sleep(wait)

    def reset(self) -> None:
        """Forget the reserved slot (test/diagnostic use)."""
        with self._lock:
            self._next_slot = 0.0


# Module-level singleton — every probe protocol shares this one budget.
RATE_LIMITER = SlotRateLimiter()


def rate_limited_acquire() -> None:
    """Block just long enough to honour the global outbound packet rate."""
    RATE_LIMITER.acquire()
