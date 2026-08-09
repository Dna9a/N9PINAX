# scanner/core/syn_scan.py
# TCP SYN ("half-open") scan implementation using Scapy.
#
# A SYN scan never completes the 3-way handshake — we send SYN, observe
# SYN-ACK / RST, and respond with RST. It is faster than a full connect
# scan and produces fewer log entries on the target, but requires raw
# socket privileges.

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from ..config import get_config
from ..models import Device, Port, PortProtocol, PortState
from .ratelimit import rate_limited_acquire as _rate_limited_acquire

_log = logging.getLogger(__name__)


# Pull the common port catalogue from the existing connect-scan module to
# stay consistent with banner detection and the dashboard.
from .port_scan import COMMON_PORTS  # noqa: E402


@dataclass(frozen=True)
class SynResult:
    ip: str
    port: int
    state: PortState
    ttl: int | None
    window: int | None


def _rate_limited_sleep() -> None:
    """Throttle outbound probes via the shared cross-protocol rate limiter."""
    _rate_limited_acquire()


def _syn_probe(ip: str, port: int, timeout: float) -> SynResult:
    try:
        from scapy.all import IP, TCP, sr1, send, conf  # type: ignore
    except ImportError:
        _log.debug("scapy unavailable — SYN scan skipped")
        return SynResult(
            ip=ip, port=port, state=PortState.UNKNOWN, ttl=None, window=None
        )

    conf.verb = 0
    _rate_limited_sleep()

    pkt = IP(dst=ip) / TCP(dport=port, flags="S", seq=0)
    try:
        resp = sr1(pkt, timeout=timeout, verbose=0)
    except PermissionError:
        _log.warning("SYN scan requires CAP_NET_RAW / root")
        return SynResult(
            ip=ip, port=port, state=PortState.UNKNOWN, ttl=None, window=None
        )
    except Exception as e:
        _log.debug("SYN probe %s:%d failed: %s", ip, port, e)
        return SynResult(
            ip=ip, port=port, state=PortState.UNKNOWN, ttl=None, window=None
        )

    if resp is None:
        return SynResult(
            ip=ip, port=port, state=PortState.FILTERED, ttl=None, window=None
        )

    if resp.haslayer(TCP):
        flags = int(resp[TCP].flags)
        ttl = int(resp[IP].ttl)
        window = int(resp[TCP].window)
        # SYN+ACK (0x12) → open. Send RST to be polite.
        if flags & 0x12 == 0x12:
            try:
                send(
                    IP(dst=ip) / TCP(dport=port, flags="R", seq=resp[TCP].ack),
                    verbose=0,
                )
            except Exception:
                pass
            return SynResult(
                ip=ip, port=port, state=PortState.OPEN, ttl=ttl, window=window
            )
        # RST (0x04) → closed.
        if flags & 0x04:
            return SynResult(
                ip=ip, port=port, state=PortState.CLOSED, ttl=ttl, window=window
            )

    return SynResult(ip=ip, port=port, state=PortState.FILTERED, ttl=None, window=None)


def syn_scan(
    ip: str,
    ports: list[int] | None = None,
    timeout: float | None = None,
    max_workers: int | None = None,
) -> list[SynResult]:
    """Run a SYN scan against ``ip`` for every port in ``ports``."""
    cfg = get_config()
    if timeout is None:
        timeout = cfg.syn_timeout
    if max_workers is None:
        max_workers = cfg.max_workers_ports
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    if not ports:
        return []

    results: list[SynResult] = []
    with ThreadPoolExecutor(max_workers=min(max_workers, max(1, len(ports)))) as ex:
        futures = {ex.submit(_syn_probe, ip, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            try:
                results.append(fut.result())
            except Exception as e:
                _log.debug("SYN future failed: %s", e)
    return results


def syn_scan_into_device(
    device: Device,
    ports: list[int] | None = None,
    timeout: float | None = None,
    max_workers: int | None = None,
    only_open: bool = True,
) -> Device:
    """SYN-scan a Device's ports and attach the results (including TTL/window)."""
    results = syn_scan(device.ip, ports=ports, timeout=timeout, max_workers=max_workers)

    if only_open:
        results = [r for r in results if r.state == PortState.OPEN]
    results.sort(key=lambda r: r.port)

    for r in results:
        service = COMMON_PORTS.get(r.port, "unknown")
        device.add_or_update_port(
            Port(
                number=r.port,
                state=r.state,
                protocol=PortProtocol.TCP,
                service=service,
            )
        )

    # Stash TCP stack signals on the device fingerprint for the OS classifier.
    open_with_ttl = next(
        (r for r in results if r.state == PortState.OPEN and r.ttl is not None), None
    )
    if open_with_ttl is not None:
        from ..models import FingerprintResult

        if device.fingerprint is None:
            device.fingerprint = FingerprintResult()
        if device.fingerprint.tcp_ttl is None:
            device.fingerprint.tcp_ttl = open_with_ttl.ttl
        if device.fingerprint.tcp_window is None:
            device.fingerprint.tcp_window = open_with_ttl.window

    return device
