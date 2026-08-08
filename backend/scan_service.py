# backend/scan_service.py
# Async wrapper around the synchronous scanner pipeline.
#
# Each "scan job" runs in a worker thread so the FastAPI event loop stays
# responsive, and emits lifecycle events on the shared EventBus so SSE
# subscribers see live progress.

from __future__ import annotations

import asyncio
import io
import ipaddress
import json
import logging
import sys
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from scanner.models import ScanResult

from .events import BUS
from .redis_client import cache_delete, cache_set
from .serializers import device_to_api

_JOB_TTL_SECONDS = 86400  # keep job snapshots in Redis for 24h

_log = logging.getLogger(__name__)


@dataclass
class ScanJob:
    job_id: str
    network: str
    status: str = "pending"  # pending | running | completed | failed
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    scan_id: Optional[str] = None
    error: Optional[str] = None
    progress: dict[str, str] = field(default_factory=dict)
    owner: Optional[str] = None  # user_id that started the scan (for SSE scoping)

    def to_json(self) -> dict:
        return {
            "job_id": self.job_id,
            "network": self.network,
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "scan_id": self.scan_id,
            "error": self.error,
            "progress": self.progress,
        }


class ScanService:
    """
    Tracks the lifecycle of every scan triggered from the API.

    Concurrency: we cap to one in-flight scan at a time. ARP/SYN traffic
    competing on the same NIC produces noisy results, so queuing is the
    sane default.
    """

    def __init__(self) -> None:
        self._jobs: dict[str, ScanJob] = {}
        self._lock = threading.Lock()
        self._semaphore = threading.Semaphore(1)

    def list_jobs(self) -> list[dict]:
        with self._lock:
            return [j.to_json() for j in self._jobs.values()]

    def get_job(self, job_id: str) -> Optional[ScanJob]:
        with self._lock:
            return self._jobs.get(job_id)

    def job_owner(self, job_id: str) -> Optional[str]:
        """Return the user_id that started ``job_id`` (or None if unknown)."""
        with self._lock:
            job = self._jobs.get(job_id)
            return job.owner if job else None

    def submit(
        self,
        network: Optional[str] = None,
        *,
        enable_udp: bool = False,
        enable_dhcp: bool = False,
        resolve_hostnames: bool = True,
        loop: Optional[asyncio.AbstractEventLoop] = None,
        owner: Optional[str] = None,
    ) -> ScanJob:
        # Validate network up-front — refuse junk before spawning a thread.
        if network:
            try:
                ipaddress.ip_network(network, strict=False)
            except ValueError as e:
                raise ValueError(f"Invalid CIDR: {network!r} ({e})")

        job = ScanJob(job_id=uuid.uuid4().hex, network=network or "auto", owner=owner)
        with self._lock:
            self._jobs[job.job_id] = job

        thread = threading.Thread(
            target=self._run_job,
            args=(job, network, enable_udp, enable_dhcp, resolve_hostnames, loop),
            daemon=True,
            name=f"scan-{job.job_id[:8]}",
        )
        thread.start()
        return job

    # ── internals ───────────────────────────────────────────────────────

    def _run_job(
        self,
        job: ScanJob,
        network: Optional[str],
        enable_udp: bool,
        enable_dhcp: bool,
        resolve_hostnames: bool,
        loop: Optional[asyncio.AbstractEventLoop],
    ) -> None:
        publish = self._publisher(loop)
        schedule = self._scheduler(loop)
        publish("scan_queued", job.to_json())
        self._persist_job(schedule, job)

        with self._semaphore:
            job.status = "running"
            job.started_at = datetime.now(timezone.utc)
            publish("scan_started", job.to_json())
            self._persist_job(schedule, job)

            def _on_progress(step: str, state: str) -> None:
                job.progress[step] = state
                publish("scan_progress", {"job_id": job.job_id, "step": step, "state": state})

            def _emit_log(line: str) -> None:
                publish("scan_log", {"job_id": job.job_id, "line": line})

            def _on_device(device, is_update: bool) -> None:
                # Live device feed: full device object as soon as ARP finds it
                # (discovered) and again once fully enriched (updated).
                event = "device_updated" if is_update else "device_discovered"
                payload = device_to_api(device)
                payload["job_id"] = job.job_id
                publish(event, payload)

            try:
                # Lazy-import so importing the backend module does not pull
                # Scapy into environments that don't need it (CI, tests).
                from scanner.main import run_scan

                _orig_stdout = sys.stdout
                sys.stdout = _StdoutTee(_orig_stdout, _emit_log)
                try:
                    result: ScanResult = run_scan(
                        network=network,
                        resolve_hostnames=resolve_hostnames,
                        enable_udp=enable_udp,
                        enable_dhcp=enable_dhcp,
                        save_to_db=True,
                        write_report=True,
                        progress=_on_progress,
                        on_device=_on_device,
                    )
                finally:
                    sys.stdout = _orig_stdout

                job.scan_id = result.scan_id
                job.status = "completed"
                job.finished_at = datetime.now(timezone.utc)

                # Stream a high-level summary, not the full payload.
                publish(
                    "scan_completed",
                    {
                        "job_id": job.job_id,
                        "scan_id": result.scan_id,
                        "total_hosts": result.total_hosts,
                        "duration_seconds": result.duration_seconds,
                        "alerts": len(result.alerts),
                    },
                )
                self._persist_job(schedule, job)
                # A new scan landed — drop the cached "last scan" so the
                # dashboard sees fresh data immediately.
                schedule(lambda: cache_delete("cache:last_scan"))

                # Stream alerts one by one so the dashboard can update its feed.
                for alert in result.alerts:
                    publish("alert", alert.to_json())

            except Exception as e:
                job.status = "failed"
                job.error = str(e)
                job.finished_at = datetime.now(timezone.utc)
                publish("scan_failed", {"job_id": job.job_id, "error": str(e)})
                self._persist_job(schedule, job)
                _log.exception("Scan job %s failed: %s", job.job_id, e)

    def _publisher(self, loop: Optional[asyncio.AbstractEventLoop]):
        """Return a thread-safe publish closure."""
        def _publish(event_type: str, data: dict) -> None:
            if loop is None:
                return
            try:
                asyncio.run_coroutine_threadsafe(BUS.publish(event_type, data), loop)
            except RuntimeError:
                pass
        return _publish

    def _scheduler(self, loop: Optional[asyncio.AbstractEventLoop]):
        """Return a closure that schedules an arbitrary coroutine on the loop."""
        def _schedule(coro_factory) -> None:
            if loop is None:
                return
            try:
                asyncio.run_coroutine_threadsafe(coro_factory(), loop)
            except RuntimeError:
                pass
        return _schedule

    @staticmethod
    def _persist_job(schedule, job: ScanJob) -> None:
        """Snapshot the job state to Redis (job:{id}). No-op without Redis."""
        payload = json.dumps(job.to_json())  # snapshot now, in the worker thread
        schedule(lambda: cache_set(f"job:{job.job_id}", payload, _JOB_TTL_SECONDS))


class _StdoutTee(io.TextIOBase):
    """
    Wraps sys.stdout so every printed line is also published as a
    ``scan_log`` SSE event while the scan thread is running.
    Only active for the duration of one scan job.
    """

    def __init__(self, original, on_line):
        self._original = original
        self._on_line = on_line
        self._buf = ""

    def write(self, s: str) -> int:
        self._original.write(s)
        self._buf += s
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            stripped = line.rstrip()
            if stripped:
                self._on_line(stripped)
        return len(s)

    def flush(self) -> None:
        self._original.flush()

    def fileno(self) -> int:
        return self._original.fileno()

    @property
    def encoding(self):
        return getattr(self._original, "encoding", "utf-8")


# Module-level singleton — the FastAPI app shares the same service.
SERVICE = ScanService()
