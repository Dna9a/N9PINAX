# scanner/core/icmp_scan.py
# ICMP ping sweep — discovers hosts that respond to echo requests.
#
# Used as a fallback when ARP is unavailable (different L3 segment, no
# CAP_NET_RAW), and to add ICMP-response metadata to ARP-discovered devices
# so the OS classifier can use TTL signals.

from __future__ import annotations

import ipaddress
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from ..config import get_config
from ..models import Device

_log = logging.getLogger(__name__)


@dataclass(frozen=True)
class IcmpReply:
    ip: str
    ttl: int | None
    rtt_ms: float | None  # round-trip time
    alive: bool


_rate_lock = threading.Lock()
_last_sent: list[float] = []


def _rate_limited_sleep() -> None:
    """Throttle outbound probes to ``rate_limit_pps`` per second globally."""
    cfg = get_config()
    pps = max(1, cfg.rate_limit_pps)
    with _rate_lock:
        now = time.monotonic()
        # Keep only timestamps from the last second
        cutoff = now - 1.0
        _last_sent[:] = [t for t in _last_sent if t > cutoff]
        if len(_last_sent) >= pps:
            sleep_for = 1.0 - (now - _last_sent[0])
            if sleep_for > 0:
                time.sleep(sleep_for)
        _last_sent.append(time.monotonic())


def _icmp_probe(ip: str, timeout: float) -> IcmpReply:
    """Send a single ICMP echo request via Scapy and return the reply metadata."""
    try:
        from scapy.all import IP, ICMP, sr1, conf  # type: ignore
    except ImportError:
        _log.debug("scapy unavailable — ICMP probe skipped")
        return IcmpReply(ip=ip, ttl=None, rtt_ms=None, alive=False)

    conf.verb = 0

    _rate_limited_sleep()

    pkt = IP(dst=ip) / ICMP()
    start = time.perf_counter()
    try:
        resp = sr1(pkt, timeout=timeout, verbose=0)
    except PermissionError:
        _log.warning("ICMP probe requires root / CAP_NET_RAW")
        return IcmpReply(ip=ip, ttl=None, rtt_ms=None, alive=False)
    except Exception as e:
        _log.debug("ICMP probe %s failed: %s", ip, e)
        return IcmpReply(ip=ip, ttl=None, rtt_ms=None, alive=False)

    if resp is None:
        return IcmpReply(ip=ip, ttl=None, rtt_ms=None, alive=False)

    rtt_ms = (time.perf_counter() - start) * 1000.0
    try:
        ttl = int(resp[IP].ttl)
    except Exception:
        ttl = None
    return IcmpReply(ip=ip, ttl=ttl, rtt_ms=rtt_ms, alive=True)


def icmp_sweep(
    network: str,
    timeout: float | None = None,
    max_workers: int | None = None,
) -> list[IcmpReply]:
    """Ping every host in a CIDR range, returning replies for those that answered."""
    cfg = get_config()
    if timeout is None:
        timeout = cfg.icmp_timeout
    if max_workers is None:
        max_workers = cfg.max_workers_hosts

    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError as e:
        raise ValueError(f"Réseau invalide : {network!r} ({e})")

    # Skip network / broadcast addresses for /24 and shorter
    hosts = (
        [str(h) for h in net.hosts()]
        if net.prefixlen < 31
        else [str(net.network_address)]
    )

    if not hosts:
        return []

    replies: list[IcmpReply] = []
    with ThreadPoolExecutor(max_workers=min(max_workers, max(1, len(hosts)))) as ex:
        futures = {ex.submit(_icmp_probe, ip, timeout): ip for ip in hosts}
        for fut in as_completed(futures):
            try:
                rep = fut.result()
            except Exception as e:
                _log.debug("ICMP future failed: %s", e)
                continue
            if rep.alive:
                replies.append(rep)
    return replies


def enrich_devices(devices: list[Device], timeout: float | None = None) -> list[Device]:
    """Attach ICMP latency / TTL data to already-discovered devices."""
    if not devices:
        return devices

    cfg = get_config()
    if timeout is None:
        timeout = cfg.icmp_timeout

    with ThreadPoolExecutor(max_workers=cfg.max_workers_hosts) as ex:
        future_map = {ex.submit(_icmp_probe, d.ip, timeout): d for d in devices}
        for fut in as_completed(future_map):
            device = future_map[fut]
            try:
                reply = fut.result()
            except Exception:
                continue
            if device.fingerprint is None:
                from ..models import FingerprintResult

                device.fingerprint = FingerprintResult()
            device.fingerprint.icmp_response = reply.alive
            if reply.ttl is not None and device.fingerprint.tcp_ttl is None:
                device.fingerprint.tcp_ttl = reply.ttl
            if reply.rtt_ms is not None:
                device.latency_ms = reply.rtt_ms

    return devices
