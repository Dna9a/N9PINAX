# backend/events.py
# In-memory event bus that streams scanner events to every connected SSE
# client. Each subscriber gets its own asyncio.Queue so a slow client cannot
# stall publishers — when a queue is full we drop the oldest event for that
# subscriber and keep streaming.

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, AsyncIterator
from uuid import uuid4

_log = logging.getLogger(__name__)


@dataclass
class Event:
    """One SSE event."""

    type: str
    data: Any
    id: str = field(default_factory=lambda: uuid4().hex)
    timestamp: float = field(default_factory=time.time)

    def to_sse(self) -> dict[str, str]:
        """Render the event in the form expected by sse-starlette."""
        return {
            "id": self.id,
            "event": self.type,
            "data": json.dumps(
                {"type": self.type, "ts": self.timestamp, "data": self.data},
                default=str,
            ),
        }


class EventBus:
    """Process-local pub/sub for scanner events."""

    def __init__(self, max_queue: int = 256) -> None:
        self._subscribers: set[asyncio.Queue[Event]] = set()
        self._max_queue = max_queue
        self._lock = asyncio.Lock()

    async def publish(self, event_type: str, data: Any) -> Event:
        evt = Event(type=event_type, data=data)
        # Snapshot subscribers under the lock so we never iterate a mutated set.
        async with self._lock:
            queues = list(self._subscribers)
        for q in queues:
            try:
                q.put_nowait(evt)
            except asyncio.QueueFull:
                # Drop the oldest event from this subscriber so we never block.
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
                try:
                    q.put_nowait(evt)
                except asyncio.QueueFull:
                    _log.warning("subscriber queue still full after drop — skipping")
        return evt

    def publish_sync(self, event_type: str, data: Any) -> None:
        """
        Schedule a publish from a non-async context (e.g. inside the scan
        thread). Best-effort: silently no-ops if there is no running loop.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        try:
            loop.call_soon_threadsafe(asyncio.create_task, self.publish(event_type, data))
        except RuntimeError:
            pass

    async def subscribe(self) -> AsyncIterator[Event]:
        q: asyncio.Queue[Event] = asyncio.Queue(maxsize=self._max_queue)
        async with self._lock:
            self._subscribers.add(q)
        try:
            while True:
                evt = await q.get()
                yield evt
        finally:
            async with self._lock:
                self._subscribers.discard(q)


# Module-level singleton — every backend module shares the same bus.
BUS = EventBus()
