# scanner/fingerprint/hostname.py
# Reverse-DNS hostname resolution with bounded timeouts, on-disk caching,
# and an optional asyncio frontend for high-fan-out scans.

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable

from ..config import get_config
from ..models import Device

_log = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Persistent cache
# ──────────────────────────────────────────────────────────────────────────────
# Stored alongside the rest of the scanner data so dashboards picking up a
# fresh subnet do not pay the DNS cost twice. Each entry has a TTL — beyond
# the TTL the value is re-resolved instead of trusted indefinitely.

_CACHE_FILE = Path(__file__).parent.parent / "data" / "hostname_cache.json"
_CACHE_TTL_SECONDS = 60 * 60 * 24  # 24h — DNS PTR records change rarely on a LAN
# Failed ("unknown") lookups get a MUCH shorter TTL: a host that had no PTR
# record (or was briefly unreachable) shouldn't be written off for a full day
# (audit F-047). Re-resolve these every few minutes instead.
_NEG_CACHE_TTL_SECONDS = 5 * 60  # 5 min
_UNKNOWN = "unknown"


_cache_lock = threading.Lock()
_cache: dict[str, tuple[str, float]] = {}
_cache_loaded = False


def _load_cache() -> None:
    """Lazy-load the persistent cache from disk."""
    global _cache_loaded
    if _cache_loaded:
        return
    with _cache_lock:
        if _cache_loaded:
            return
        if _CACHE_FILE.exists():
            try:
                raw = json.loads(_CACHE_FILE.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    now = time.time()
                    for ip, entry in raw.items():
                        if (
                            isinstance(entry, list)
                            and len(entry) == 2
                            and isinstance(entry[0], str)
                            and isinstance(entry[1], (int, float))
                            and now - entry[1] < _CACHE_TTL_SECONDS
                        ):
                            _cache[ip] = (entry[0], float(entry[1]))
            except Exception as e:
                _log.debug("hostname cache load failed: %s", e)
        _cache_loaded = True


def _flush_cache() -> None:
    """Persist the in-memory cache to disk atomically; safe to call often.

    Writes to a temp file and ``os.replace``s it into place so a crash
    mid-write can never leave a truncated/corrupt cache file (audit F-046).
    """
    try:
        _CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _cache_lock:
            snapshot = {ip: [name, ts] for ip, (name, ts) in _cache.items()}
        tmp = _CACHE_FILE.with_name(_CACHE_FILE.name + ".tmp")
        tmp.write_text(json.dumps(snapshot), encoding="utf-8")
        os.replace(tmp, _CACHE_FILE)
    except OSError as e:
        _log.debug("hostname cache flush failed: %s", e)


def clear_cache() -> None:
    """Wipe the in-memory cache (test/diagnostic use)."""
    with _cache_lock:
        _cache.clear()


# ──────────────────────────────────────────────────────────────────────────────
# Resolution
# ──────────────────────────────────────────────────────────────────────────────


def _lookup_with_timeout(ip: str, timeout: float) -> str:
    """
    Run ``socket.gethostbyaddr`` with a hard wall-clock timeout.

    ``gethostbyaddr`` is a blocking system call without a built-in timeout.
    We run it inside a thread and join with a deadline so a slow resolver
    cannot stall the scan pipeline indefinitely.
    """
    if not ip:
        return _UNKNOWN

    result: dict[str, str] = {"name": _UNKNOWN}

    def _resolve() -> None:
        try:
            result["name"] = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            result["name"] = _UNKNOWN
        except Exception:
            result["name"] = _UNKNOWN

    t = threading.Thread(target=_resolve, daemon=True)
    t.start()
    t.join(timeout=timeout)
    return result.get("name", _UNKNOWN)


def resolve_hostname(ip: str, timeout: float | None = None) -> str:
    """
    Resolve a single IP to a hostname using the persistent cache.

    Returns ``"unknown"`` when the lookup fails or times out — never raises.
    """
    if not isinstance(ip, str) or not ip:
        return _UNKNOWN

    cfg = get_config()
    if timeout is None:
        timeout = cfg.dns_timeout

    _load_cache()

    now = time.time()
    with _cache_lock:
        cached = _cache.get(ip)
        if cached:
            # Successful lookups are trusted for 24h; failed ("unknown") ones
            # only for a few minutes so a transient miss self-heals (F-047).
            ttl = (
                _NEG_CACHE_TTL_SECONDS if cached[0] == _UNKNOWN else _CACHE_TTL_SECONDS
            )
            if now - cached[1] < ttl:
                return cached[0]

    name = _lookup_with_timeout(ip, timeout) or _UNKNOWN

    with _cache_lock:
        _cache[ip] = (name, now)

    return name


def resolve_many(
    ips: Iterable[str],
    timeout: float | None = None,
    max_workers: int | None = None,
) -> dict[str, str]:
    """
    Resolve a batch of IPs concurrently, returning a ``{ip: hostname}`` map.

    Falls back to ``"unknown"`` per-IP on timeout/error — never raises so the
    caller can keep enriching devices even if DNS is partially broken.
    """
    cfg = get_config()
    if timeout is None:
        timeout = cfg.dns_timeout
    if max_workers is None:
        max_workers = cfg.max_workers_dns

    ip_list = [ip for ip in ips if isinstance(ip, str) and ip]
    if not ip_list:
        return {}

    results: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=min(max_workers, max(1, len(ip_list)))) as ex:
        future_map = {ex.submit(resolve_hostname, ip, timeout): ip for ip in ip_list}
        for fut in as_completed(future_map):
            ip = future_map[fut]
            try:
                results[ip] = fut.result()
            except Exception:
                results[ip] = _UNKNOWN

    _flush_cache()
    return results


# ──────────────────────────────────────────────────────────────────────────────
# Async API
# ──────────────────────────────────────────────────────────────────────────────


async def async_resolve_hostname(ip: str, timeout: float | None = None) -> str:
    """Async wrapper around :func:`resolve_hostname`."""
    return await asyncio.to_thread(resolve_hostname, ip, timeout)


async def async_resolve_many(
    ips: Iterable[str], timeout: float | None = None, concurrency: int | None = None
) -> dict[str, str]:
    """Concurrent async resolution using a semaphore to cap simultaneous DNS load."""
    cfg = get_config()
    sem = asyncio.Semaphore(concurrency or cfg.max_workers_dns)

    async def _one(ip: str) -> tuple[str, str]:
        async with sem:
            return ip, await async_resolve_hostname(ip, timeout)

    ip_list = [ip for ip in ips if isinstance(ip, str) and ip]
    if not ip_list:
        return {}

    out: dict[str, str] = {}
    for coro in asyncio.as_completed([_one(ip) for ip in ip_list]):
        ip, name = await coro
        out[ip] = name

    await asyncio.to_thread(_flush_cache)
    return out


# ──────────────────────────────────────────────────────────────────────────────
# Device enrichment
# ──────────────────────────────────────────────────────────────────────────────


def enrich_devices(devices: list[Device], timeout: float | None = None) -> list[Device]:
    """Populate ``device.hostname`` for every device with a reverse-DNS lookup."""
    if not devices:
        return devices

    ips = [d.ip for d in devices]
    name_map = resolve_many(ips, timeout=timeout)

    for device in devices:
        # Pydantic v2 keeps validators on assignment off by default for
        # speed; assign through the validator-friendly attribute setter
        # so non-printable chars get stripped.
        device.hostname = name_map.get(device.ip, _UNKNOWN) or _UNKNOWN

    return devices
