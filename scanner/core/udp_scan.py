# scanner/core/udp_scan.py
# UDP port scan.
#
# UDP scans are inherently noisy: an unreachable port replies with
# ICMP type 3 / code 3 (port unreachable), but firewalls drop or rate-limit
# these replies — so a non-response can mean OPEN | FILTERED.
#
# We send a small, protocol-aware payload for the few "talker" services
# (DNS, NTP, SNMP, NetBIOS, mDNS) so we can disambiguate OPEN from FILTERED
# when a real reply comes back.

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from ..config import get_config
from ..models import Device, Port, PortProtocol, PortState

_log = logging.getLogger(__name__)


COMMON_UDP_PORTS: dict[int, str] = {
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    123: "NTP",
    137: "NetBIOS",
    138: "NetBIOS",
    161: "SNMP",
    162: "SNMP-trap",
    500: "IKE",
    514: "Syslog",
    520: "RIP",
    1900: "SSDP",
    5353: "mDNS",
    5060: "SIP",
}


# Crafted payloads that elicit a response from common UDP services.
# Empty payload works for most services but DNS/SNMP need a proper query.
_PAYLOADS: dict[int, bytes] = {
    53: (
        # Minimal DNS standard query for "version.bind" CHAOS TXT
        b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x07version\x04bind\x00\x00\x10\x00\x03"
    ),
    123: b"\x1b" + b"\x00" * 47,  # NTP client request
    161: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x01"
    b"\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
    1900: (
        b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
        b'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n'
    ),
    5353: (
        # Minimal mDNS query for _services._dns-sd._udp.local
        b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01"
    ),
}


@dataclass(frozen=True)
class UdpResult:
    ip: str
    port: int
    state: PortState
    response_bytes: int


_rate_lock = threading.Lock()
_last_sent: list[float] = []


def _rate_limited_sleep() -> None:
    cfg = get_config()
    pps = max(1, cfg.rate_limit_pps)
    with _rate_lock:
        now = time.monotonic()
        cutoff = now - 1.0
        _last_sent[:] = [t for t in _last_sent if t > cutoff]
        if len(_last_sent) >= pps:
            sleep_for = 1.0 - (now - _last_sent[0])
            if sleep_for > 0:
                time.sleep(sleep_for)
        _last_sent.append(time.monotonic())


def _udp_probe(ip: str, port: int, timeout: float) -> UdpResult:
    """
    Pure-socket UDP probe — no raw sockets required.

    A reply means OPEN. Silence means OPEN|FILTERED (we can't tell apart).
    ICMP unreachable, surfaced by the kernel as ConnectionRefusedError on
    Linux, means CLOSED.
    """
    import socket

    _rate_limited_sleep()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    payload = _PAYLOADS.get(port, b"\x00")
    try:
        sock.sendto(payload, (ip, port))
        try:
            data, _ = sock.recvfrom(512)
            return UdpResult(
                ip=ip, port=port, state=PortState.OPEN, response_bytes=len(data)
            )
        except socket.timeout:
            return UdpResult(
                ip=ip, port=port, state=PortState.FILTERED, response_bytes=0
            )
        except ConnectionRefusedError:
            return UdpResult(ip=ip, port=port, state=PortState.CLOSED, response_bytes=0)
        except OSError:
            return UdpResult(
                ip=ip, port=port, state=PortState.FILTERED, response_bytes=0
            )
    except OSError as e:
        _log.debug("UDP probe %s:%d failed at send: %s", ip, port, e)
        return UdpResult(ip=ip, port=port, state=PortState.UNKNOWN, response_bytes=0)
    finally:
        sock.close()


def udp_scan(
    ip: str,
    ports: list[int] | None = None,
    timeout: float | None = None,
    max_workers: int | None = None,
) -> list[UdpResult]:
    cfg = get_config()
    if timeout is None:
        timeout = cfg.udp_timeout
    if max_workers is None:
        # UDP probes are slow because of the silence-vs-open ambiguity;
        # cap concurrency so we don't drown the local kernel queue.
        max_workers = max(8, cfg.max_workers_ports // 4)
    if ports is None:
        ports = list(COMMON_UDP_PORTS.keys())

    if not ports:
        return []

    out: list[UdpResult] = []
    with ThreadPoolExecutor(max_workers=min(max_workers, max(1, len(ports)))) as ex:
        futures = {ex.submit(_udp_probe, ip, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            try:
                out.append(fut.result())
            except Exception as e:
                _log.debug("UDP future failed: %s", e)
    return out


def udp_scan_into_device(
    device: Device,
    ports: list[int] | None = None,
    timeout: float | None = None,
    only_open: bool = True,
) -> Device:
    """Run a UDP scan against the Device and merge the results into its ports."""
    results = udp_scan(device.ip, ports=ports, timeout=timeout)
    if only_open:
        results = [r for r in results if r.state == PortState.OPEN]
    results.sort(key=lambda r: r.port)

    for r in results:
        service = COMMON_UDP_PORTS.get(r.port, "unknown")
        device.add_or_update_port(
            Port(
                number=r.port,
                state=r.state,
                protocol=PortProtocol.UDP,
                service=service,
            )
        )
    return device
